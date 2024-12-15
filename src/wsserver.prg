#include "inkey.ch"
#include "hbsocket.ch"

#define ADDRESS    "0.0.0.0"
 
#define TIMEOUT    50
#define CRLF       Chr( 13 ) + Chr( 10 )

#define OPC_CONT   0x00
#define OPC_TEXT   0x01
#define OPC_BIN    0x02
#define OPC_CLOSE  0x08
#define OPC_PING   0x09
#define OPC_PONG   0x0A



#ifndef NO_SSL
	#include "hbssl.ch"
	#define PORT		443
#else 
	#define PORT 		9000
#endif	

static oSSL
static hmtxQueue

//----------------------------------------------------------------//

function Main()

   local hListen, hSocket

   if ! hb_mtvm()
      ? "multithread support required"
      return nil
   endif
   
   	hmtxQueue 	:= hb_mutexCreate()
	
	#ifndef NO_SSL
	
		SSL_INIT()
		
		oSSL := TSSL():New()
		
		oSSL:hSSLCtx := SSL_CTX_NEW(HB_SSL_CTX_NEW_METHOD_SSLV23_SERVER)
		
		SSL_CTX_SET_OPTIONS(oSSL:hSSLCtx, HB_SSL_OP_NO_TLSv1)		
		
		IF SSL_CTX_USE_PRIVATEKEY_FILE( oSSL:hSSLCtx, oSSL:cPrivateKey, HB_SSL_FILETYPE_PEM) != 1
			oSSL:cError := "Invalid private key file"			
			? oSSL:cError
			RETURN .F.
		ENDIF
		
		IF SSL_CTX_USE_CERTIFICATE_FILE(oSSL:hSSLCtx, oSSL:cCertificate, HB_SSL_FILETYPE_PEM) != 1
			oSSL:cError := "Invalid certificate file"	
			? oSSL:cError			
			RETURN .F.
		ENDIF		
		
	#endif
	
   if Empty( hListen := hb_socketOpen( HB_SOCKET_AF_INET, HB_SOCKET_PT_STREAM, HB_SOCKET_IPPROTO_TCP ) )
      ? "socket create error " + hb_ntos( hb_socketGetError() )
   endif

   if ! hb_socketBind( hListen, { HB_SOCKET_AF_INET, ADDRESS, PORT } )
      ? "bind error " + hb_ntos( hb_socketGetError() )
   endif

   if ! hb_socketListen( hListen )
      ? "listen error " + hb_ntos( hb_socketGetError() )
   endif

   ? "Harbour websockets server running on port " + hb_ntos( PORT )
   
    while .T.
      if Empty( hSocket := hb_socketAccept( hListen,, TIMEOUT ) )
         if hb_socketGetError() == HB_SOCKET_ERR_TIMEOUT
            //? "loop"
         ELSE
            ? "accept error " + hb_ntos( hb_socketGetError() )
         endif
      ELSE
         ? "accept socket request"
         hb_threadDetach( hb_threadStart( @ServeClient(), hSocket ) )
      endif
      if Inkey() == K_ESC
         ? "quitting - esc pressed"
         EXIT
      endif
    end

   ? "close listening socket"

   hb_socketShutdown( hListen )
   hb_socketClose( hListen )

return nil

//----------------------------------------------------------------//

function HandShaking( hSocket, cHeaders, hSSL  )   

   local aHeaders := hb_ATokens( cHeaders, CRLF )
   local hHeaders := {=>}, cLine 
   local cAnswer, nLen, nErr, cLocation
  
   cHeaders:= alltrim(cHeaders)
  
    if empty( cHeaders )		
		retu .f. 
	endif


   for each cLine in aHeaders
      hHeaders[ SubStr( cLine, 1, At( ":", cLine ) - 1 ) ] = SubStr( cLine, At( ":", cLine ) + 2 )
   next

  
   if empty( hHeaders) .or. ! HB_HHasKey( hHeaders, 'Sec-WebSocket-Key' )  	
	 retu .f.
   endif

    #ifndef NO_SSL
		cLocation := "WebSocket-Location: wss://"   + hHeaders[ 'Host'] + ":" + hb_ntos( PORT )
	#else
		cLocation := "WebSocket-Location: ws://"   + hHeaders[ 'Host'] + ":" + hb_ntos( PORT )
	#endif
	

   cAnswer = "HTTP/1.1 101 Web Socket Protocol Handshake" + CRLF + ;
             "Upgrade: websocket" + CRLF + ;
             "Connection: Upgrade" + CRLF + ;
             "WebSocket-Origin: " + ADDRESS + CRLF + ;
			 "WebSocket-Location: " + cLocation +  CRLF + ;
             "Sec-WebSocket-Accept: " + ;
             hb_Base64Encode( hb_SHA1( hHeaders[ "Sec-WebSocket-Key" ] + ;
                              "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", .T. ) ) + CRLF + CRLF

  
    #ifndef NO_SSL
		nLen := MY_SSL_WRITE( hSSL, hSocket, cAnswer, TIMEOUT, @nErr )	
	#else
		nLen := hb_socketSend( hSocket, cAnswer ) 				
	#endif
	
	

return .t.   

//----------------------------------------------------------------//

function Unmask( cBytes, nOpcode )
   
   local lComplete := hb_bitTest( hb_bPeek( cBytes, 1 ), 7 )
   local nFrameLen := hb_bitAnd( hb_bPeek( cBytes, 2 ), 127 ) 
   local nLength, cMask, cData, cChar, cHeader := "", nCommaPos

   nOpcode := hb_bitAnd( hb_bPeek( cBytes, 1 ), 15 )


   do case
      case nFrameLen <= 125
         nLength = nFrameLen
         cMask = SubStr( cBytes, 3, 4 )
         cData = SubStr( cBytes, 7 )

      case nFrameLen = 126
         nLength = ( hb_bPeek( cBytes, 3 ) * 256 ) + hb_bPeek( cBytes, 4 )
         cMask   = SubStr( cBytes, 5, 4 )
         cData   = SubStr( cBytes, 9 )

      case nFrameLen = 127  
         nLength = NetworkBin2ULL( SubStr( cBytes, 3, 8 ) )  
         cMask   = SubStr( cBytes, 11, 4 )
         cData   = SubStr( cBytes, 15 )
   endcase 


   cBytes = ""
   for each cChar in cData
      cBytes += Chr( hb_bitXor( Asc( cChar ),;
                     hb_bPeek( cMask, ( ( cChar:__enumIndex() - 1 ) % 4 ) + 1 ) ) ) 
   next   


   nCommaPos = At( ",", cBytes )
   cHeader = SubStr( cBytes, 1, nCommaPos - 1 )
   if Right( cHeader, 6 ) == "base64"
      cBytes = hb_base64Decode( SubStr( cBytes, nCommaPos + 1 ) )
   else
      cHeader = ""      
   endif

return cBytes 

//----------------------------------------------------------------//

function NetworkULL2Bin( n )

   local nBytesLeft := 64
   local cBytes := ""

   while nBytesLeft > 0
      nBytesLeft -= 8
      cBytes += Chr( hb_BitAnd( hb_BitShift( n, -nBytesLeft ), 0xFF ) )
   end

return cBytes

//----------------------------------------------------------------//

function NetworkBin2ULL( cBytes )

   local cByte, n := 0
   
   for each cByte in cBytes
      n += hb_BitShift( Asc( cByte ), 64 - cByte:__enumIndex() * 8 )
   next
   
return n

//----------------------------------------------------------------//

function Mask( cText, nOPCode )

   local nLen := Len( cText )
   local cHeader 
   local nFirstByte := 0
                  
   hb_default( @nOPCode, OPC_TEXT )

   nFirstByte = hb_bitSet( nFirstByte, 7 ) // 1000 0000
   // setting OP code
   nFirstByte := hb_bitOr( nFirstByte, nOPCode )  // 1000 XXXX -> is set

   do case
      case nLen <= 125
         cHeader = Chr( nFirstByte ) + Chr( nLen )   

      case nLen < 65536
         cHeader = Chr( nFirstByte ) + Chr( 126 ) + ;
                   Chr( hb_BitShift( nLen, -8 ) ) + Chr( hb_BitAnd( nLen, 0xFF ) )
         
      otherwise 
         cHeader = Chr( nFirstByte ) + Chr( 127 ) + NetworkULL2Bin( nLen )   
   endcase

return cHeader + cText   

//----------------------------------------------------------------//

function ServeClient( hSocket )

 
   local cRequest, cBuffer := Space( 4096 ), nLen, nOpcode, cResponse, lRead
   local nErr, hSSL
   local nTime

	#ifndef NO_SSL

      hSSL := SSL_NEW(oSSL:hSSLCtx)


      SSL_SET_MODE(hSSL, hb_bitOr(SSL_GET_MODE(hSSL), HB_SSL_MODE_ENABLE_PARTIAL_WRITE))
      hb_socketSetBlockingIO(hSocket, .F.)
      SSL_SET_FD(hSSL, hb_socketGetFD(hSocket))

		
         nTime := hb_MilliSeconds()
         DO WHILE .T.
            
            IF ( nErr := MY_SSL_ACCEPT( hSSL, hSocket, TIMEOUT ) ) == 0

               EXIT
            ELSE

               IF nErr == HB_SOCKET_ERR_TIMEOUT			   
                  
                  IF ( hb_MilliSeconds() - nTime ) > TIMEOUT                    
                     ? "SSL accept timeout"
                     EXIT
                  ENDIF
               ELSE	                  
                  ? "SSL accept error:", nErr, hb_socketErrorString( nErr )								
                  EXIT
               ENDIF
            ENDIF

         ENDDO	
		 
		
		if nErr != 0 
            hb_socketShutdown( hSocket )
            hb_socketClose( hSocket )
			retu nil			
		endif
		
		
		nLen := MY_SSL_READ( hSSL, hSocket, @cBuffer, TIMEOUT , @nErr)				
		
		oSSL:Accept( hSSL )					

	#else

		hb_socketRecv( hSocket, @cBuffer,,, TIMEOUT )
	#endif
  
   
   if ! HandShaking( hSocket, RTrim( cBuffer ), hSSL )  
		hb_socketShutdown( hSocket )
		hb_socketClose( hSocket )  		
		retu nil
   endif

   ? "new client connected" 
  
   while .T.
   
      cRequest = ""
      nLen = 1	  

      while nLen > 0
	 
         cBuffer := Space( 4096 )
		 
		 #ifndef NO_SSL			
			nLen := MY_SSL_READ( hSSL, hSocket, @cBuffer, TIMEOUT , @nErr)
		 #else
			nLen := hb_socketRecv( hSocket, @cBuffer,,, TIMEOUT ) 		
		 #endif		 
         
         if  nLen > 0
            cRequest += Left( cBuffer, nLen )
         else
            if nLen == -1 .and. hb_socketGetError() == HB_SOCKET_ERR_TIMEOUT
               nLen = 0
            endif
         endif
	
      end
	  
	  hb_idleSleep(0.05)
      
      if ! Empty( cRequest )

         cRequest := UnMask( cRequest, @nOpcode )	
		 cResponse := ''


         do case
            case cRequest == "exit"          // 1000 value in hex and bytes swapped 
		
				#ifndef NO_SSL					
					nLen := MY_SSL_WRITE( hSSL, hSocket, Mask( I2Bin( 0xE803 ) + "exiting", OPC_CLOSE ), TIMEOUT, @nErr )
				#else
					hb_socketSend( hSocket, Mask( I2Bin( 0xE803 ) + "exiting", OPC_CLOSE ) )   // close handShake
				#endif
               
            case cRequest == I2Bin( 0xE803 ) + "exiting"                                  // client answered to close handShake

               exit		   
               
            otherwise
	
				do case 								
					case cRequest == 'info'
					
						#ifndef NO_SSL
							cResponse := oSSL:Info()
						#else
							cResponse := 'NO SSL'					
						#endif 
						
					case cRequest == 'time' 
					
						cResponse := time()						
					
					otherwise 
					
						cResponse := cRequest 

				endcase 
			
				#ifndef NO_SSL					
					nLen := MY_SSL_WRITE( hSSL, hSocket, Mask( cResponse ), TIMEOUT, @nErr  )
				#else			   
					nLen := hb_socketSend( hSocket, Mask( cResponse ) )
				#endif
			
         endcase
		 
      endif
   end

   ? "close socket"

   hb_socketShutdown( hSocket )
   hb_socketClose( hSocket )

return nil

//----------------------------------------------------------------//