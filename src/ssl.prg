#include "hbclass.ch"
#include "hbssl.ch"
#include "hbsocket.ch"

#define CRLF       Chr( 13 ) + Chr( 10 )

CLASS TSSL

	DATA hSSLCtx
	DATA cError	
	DATA cPrivateKey 				INIT 'cert/privatekey.pem'
	DATA cCertificate				INIT 'cert/certificate.pem'
	DATA cipher				
	DATA protocol				
	DATA cipher_usekeysize	
	DATA cipher_algkeysize	
	DATA version				
	DATA server_i_dn			
	DATA server_s_dn			

	METHOD New()    				CONSTRUCTOR
	
	METHOD Accept( hSSL )
	METHOD Info()
	
ENDCLASS 

//----------------------------------------------------------------//

METHOD New() CLASS TSSL

RETU SELF

//----------------------------------------------------------------//

METHOD Accept( hSSL ) CLASS TSSL

	local nErr 

	::cipher				:= SSL_get_cipher( hSSL )
    ::protocol				:= SSL_get_version( hSSL )
    ::cipher_usekeysize	:= SSL_get_cipher_bits( hSSL, @nErr )
    ::cipher_algkeysize	:= nErr        
    ::version				:= SSLeay_version( HB_SSLEAY_VERSION )
    ::server_i_dn			:= X509_name_oneline( X509_get_issuer_name( SSL_get_certificate( hSSL ) ) )
    ::server_s_dn			:= X509_name_oneline( X509_get_subject_name( SSL_get_certificate( hSSL ) ) )		

RETU NIL

//----------------------------------------------------------------//
	
METHOD Info() CLASS TSSL

	local cInfo := ''
	
    cInfo += CRLF
    cInfo += 'Certificate information' + CRLF
    cInfo += Replicate( '-', 60 ) + CRLF
    cInfo += 'Version: ' + ::Version + CRLF
    cInfo += 'Issuer name: ' + ::server_i_dn	+ CRLF
    cInfo += 'Subject name: ' + ::server_s_dn	+ CRLF
    cInfo += Replicate( '-', 60 ) + CRLF    
    cInfo += CRLF
	
RETU cInfo	


//----------------------------------------------------------------//
//	Mindaugas function's 
//----------------------------------------------------------------//
	 
FUNC MY_SSL_READ(hSSL, hSocket, cBuf, nTimeout, nError)
LOCAL nErr, nLen

  nLen := SSL_READ(hSSL, @cBuf)
  IF nLen < 0
    nErr := SSL_GET_ERROR(hSSL, nLen)
    IF nErr == HB_SSL_ERROR_WANT_READ
      nErr := hb_socketSelectRead(hSocket, nTimeout)
      IF nErr < 0
        nError := hb_socketGetError()
      ELSE  // Both cases: data received and timeout
        nError := HB_SOCKET_ERR_TIMEOUT
      ENDIF
      RETURN -1
    ELSEIF nErr == HB_SSL_ERROR_WANT_WRITE
      nErr := hb_socketSelectWrite(hSocket, nTimeout)
      IF nErr < 0
        nError := hb_socketGetError()
      ELSE  // Both cases: data sent and timeout
        nError := HB_SOCKET_ERR_TIMEOUT
      ENDIF
      RETURN -1
    ELSE
      //? "SSL_READ() error", nErr
      nError := 1000 + nErr
      RETURN -1
    ENDIF
  ENDIF
RETURN nLen

FUNC MY_SSL_WRITE(hSSL, hSocket, cBuf, nTimeout, nError)
LOCAL nErr, nLen

  nLen := SSL_WRITE(hSSL, cBuf)
  IF nLen <= 0
    nErr := SSL_GET_ERROR(hSSL, nLen)
    IF nErr == HB_SSL_ERROR_WANT_READ
      nErr := hb_socketSelectRead(hSocket, nTimeout)
      IF nErr < 0
        nError := hb_socketGetError()
        RETURN -1
      ELSE  // Both cases: data received and timeout
        RETURN 0
      ENDIF
    ELSEIF nErr == HB_SSL_ERROR_WANT_WRITE
      nErr := hb_socketSelectWrite(hSocket, nTimeout)
      IF nErr < 0
        nError := hb_socketGetError()
        RETURN -1
      ELSE  // Both cases: data sent and timeout
        RETURN 0
      ENDIF
    ELSE
      //? "SSL_WRITE() error", nErr
      nError := 1000 + nErr
      RETURN -1
    ENDIF
  ENDIF
RETURN nLen


FUNC MY_SSL_ACCEPT(hSSL, hSocket, nTimeout)
LOCAL nErr


  nErr := SSL_ACCEPT(hSSL)

  IF nErr > 0

    RETURN 0

  ELSEIF nErr < 0

    nErr := SSL_GET_ERROR(hSSL, nErr)

    IF nErr == HB_SSL_ERROR_WANT_READ

      nErr := hb_socketSelectRead(hSocket, nTimeout)

      IF nErr < 0

        nErr := hb_socketGetError()
      ELSE

        nErr := HB_SOCKET_ERR_TIMEOUT
      ENDIF
    ELSEIF nErr == HB_SSL_ERROR_WANT_WRITE

      nErr := hb_socketSelectWrite(hSocket, nTimeout)
      IF nErr < 0

        nErr := hb_socketGetError()
      ELSE

        nErr := HB_SOCKET_ERR_TIMEOUT
      ENDIF
    ELSE
      //? "SSL_ACCEPT() error", nErr
      nErr := 1000 + nErr
    ENDIF
  ELSE /* nErr == 0 */

    nErr := SSL_GET_ERROR( hSSL, nErr )
    //? "SSL_ACCEPT() shutdown error", nErr
    nErr := 1000 + nErr
  ENDIF

RETURN nErr

//----------------------------------------------------------------//