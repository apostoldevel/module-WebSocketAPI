/*++

Program name:

  Apostol Web Service

Module Name:

  WebSocketAPI.hpp

Notices:

  Module: Web Socket API

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_WEBSOCKETAPI_HPP
#define APOSTOL_WEBSOCKETAPI_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CWebSocketAPI -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CWebSocketAPI: public CApostolModule {
        private:

            CDateTime m_FixedDate;

            CSessionManager m_SessionManager;

            void InitMethods() override;

            static void AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);

            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);

            static void ReplyError(CHTTPServerConnection *AConnection, CHTTPReply::CStatusType ErrorCode, const CString &Message);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;

            void DoWebSocket(CHTTPServerConnection *AConnection);
            void DoSessionDisconnected(CObject *Sender);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CWebSocketAPI(CModuleProcess *AProcess);

            ~CWebSocketAPI() override = default;

            static class CWebSocketAPI *CreateModule(CModuleProcess *AProcess) {
                return new CWebSocketAPI(AProcess);
            }

            void UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                const CString &Agent, const CString &Host);

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Path, const CString &Payload, const CString &Agent, const CString &Host);

            void SignedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                const CString &Session, const CString &Nonce, const CString &Signature, const CString &Agent,
                const CString &Host, long int ReceiveWindow = 5000);

            bool Execute(CHTTPServerConnection *AConnection) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_WEBSOCKETAPI_HPP
