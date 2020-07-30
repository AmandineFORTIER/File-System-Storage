#include <botan-2/botan/tls_client.h>
#include <botan-2/botan/tls_server.h>
#include <botan-2/botan/tls_callbacks.h>
#include <botan-2/botan/tls_session_manager.h>
#include <botan-2/botan/tls_policy.h>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/certstor.h>
#include <botan-2/botan/pk_keys.h>
#include <botan-2/botan/pkcs8.h>
#include <botan-2/botan/data_src.h>
#include <botan-2/botan/x509self.h>
#include <botan-2/botan/rsa.h>
#include <iostream> // For cout

#include <memory>

/**
 * @brief Callbacks invoked by TLS::Channel.
 *
 * Botan::TLS::Callbacks is an abstract class.
 * For improved readability, only the functions that are mandatory
 * to implement are listed here. See src/lib/tls/tls_callbacks.h.
 */
class Callbacks : public Botan::TLS::Callbacks
{
   public:
      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         // send data to tls client, e.g., using BSD sockets or boost asio
         }

      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {
         // process full TLS record received by tls client, e.g.,
         // by passing it to the application
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         // handle a tls alert received from the tls server
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         // the session with the tls client was established
         // return false to prevent the session from being cached, true to
         // cache the session in the configured session manager
         return false;
         }
};

/**
 * @brief Credentials storage for the tls server.
 *
 * It returns a certificate and the associated private key to
 * authenticate the tls server to the client.
 * TLS client authentication is not requested.
 * See src/lib/tls/credentials_manager.h.
 */

class Server_Credentials : public Botan::Credentials_Manager
{
   public:
      Server_Credentials(){}

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
         const std::string& type,
         const std::string& context) override
         {
         // if client authentication is required, this function
         // shall return a list of certificates of CAs we trust
         // for tls client certificates, otherwise return an empty list
         return std::vector<Botan::Certificate_Store*>();
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context) override
         {
         // return the certificate chain being sent to the tls client
         // e.g., the certificate file "botan.randombit.net.crt"
         return {};
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
         const std::string& type,
         const std::string& context) override
         {
         // return the private key associated with the leaf certificate,
         // in this case the one associated with "botan.randombit.net.crt"
         return m_key.release();
         }

      private:
         std::unique_ptr<Botan::Private_Key> m_key;
};

Botan::X509_Certificate create_certificate()
{
   uint32_t expire_time = 60*60*24*360; //seconds, minutes, hours, days ==> in seconds
   Botan::X509_Cert_Options opt("server/Belgium",expire_time);

   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey pKey(rng,2048,3);
   Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opt,pKey,"SHA-256",rng);

   return cert;
}

int main()
{

   Botan::X509_Certificate cert =  create_certificate();
   std::cout<<cert.to_string()<<std::endl;

   // prepare all the parameters
   Callbacks callbacks;
   Botan::AutoSeeded_RNG rng;
   Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
   Server_Credentials creds;
   Botan::TLS::Strict_Policy policy;

   // accept tls connection from client
   Botan::TLS::Server server(callbacks,
                           session_mgr,
                           creds,
                           policy,
                           rng);

   // read data received from the tls client, e.g., using BSD sockets or boost asio
   // and pass it to server.received_data().
   // ...

   // send data to the tls client using server.send_data()
   // ...
}