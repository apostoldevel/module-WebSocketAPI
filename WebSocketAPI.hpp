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

    namespace BackEnd {

        namespace api {

            void observer(CStringList &SQL, const CString &Publisher, const CString &Session, const CString &Identity,
                          const CString &Data, const CString &Agent, const CString &IP);
        }
    }

    namespace Module {

        class CObserverHandler;

        typedef std::function<void (CObserverHandler *Handler)> COnObserverHandlerEvent;

        //--------------------------------------------------------------------------------------------------------------

        //-- CObserverHandler ------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CWebSocketAPI;
        //--------------------------------------------------------------------------------------------------------------

        class CObserverHandler: public CPollConnection {
        private:

            CWebSocketAPI *m_pModule;
            CSession *m_pSession;

            CString m_Publisher {};
            CString m_Data {};

            bool m_Allow;

            COnObserverHandlerEvent m_Handler;

            int AddToQueue();
            void RemoveFromQueue();

        protected:

            void SetAllow(bool Value) { m_Allow = Value; }

        public:

            CObserverHandler(CWebSocketAPI *AModule, CSession *ASession, const CString &Publisher, const CString &Data, COnObserverHandlerEvent && Handler);

            ~CObserverHandler() override;

            CSession *Session() { return m_pSession; }

            const CString &Publisher() const { return m_Publisher; }
            const CString &Data() const { return m_Data; }

            bool Allow() const { return m_Allow; };
            void Allow(bool Value) { SetAllow(Value); };

            bool Handler();

            void Close() override;
        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CWebSocketAPI ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        typedef CPollManager CQueueManager;

        class CWebSocketAPI: public CApostolModule {
        private:

            CDateTime m_CheckDate;

            CSessionManager m_SessionManager;

            CQueue m_Queue;
            CQueueManager m_QueueManager;

            size_t m_Progress;
            size_t m_MaxQueue;

            void InitListen();
            void CheckListen();

            void InitMethods() override;

            void UnloadQueue();

            void DeleteHandler(CObserverHandler *AHandler);
            static void DeleteSession(CSession *ASession);

            void CheckSession();

            CString VerifyToken(const CString &Token);

            static void AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

        protected:

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);

            static void DoError(const Delphi::Exception::Exception &E);

            static void DoCall(CHTTPServerConnection *AConnection, const CString &Action, const CString &Payload);
            static void DoCallResult(CHTTPServerConnection *AConnection, const CString &Payload);
            static void DoCallResult(CHTTPServerConnection *AConnection, const CString &UniqueId, const CString &Action, const CString &Payload);
            static void DoError(CHTTPServerConnection *AConnection, const CString &UniqueId, const CString &Action,
                CHTTPReply::CStatusType Status, const CString &Message, const CString &Payload = {});

            void DoObserver(CObserverHandler *AHandler);

            void DoGet(CHTTPServerConnection *AConnection) override;
            virtual void DoPost(CHTTPServerConnection *AConnection);
            virtual void DoWebSocket(CHTTPServerConnection *AConnection);

            void DoWS(CHTTPServerConnection *AConnection, const CString &Action);
            void DoSession(CHTTPServerConnection *AConnection, const CString &Session, const CString &Identity);

            void DoSessionDisconnected(CObject *Sender);

            void DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify) override;
            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CWebSocketAPI(CModuleProcess *AProcess, const CString& ModuleName, const CString& SectionName = CString());

            ~CWebSocketAPI() override = default;

            static class CWebSocketAPI *CreateModule(CModuleProcess *AProcess) {
                return new CWebSocketAPI(AProcess, "websocket api", "module/WebSocketAPI");
            }

            int CheckSessionAuthorization(CSession *ASession);

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);
            bool CheckTokenAuthorization(CHTTPServerConnection *AConnection, const CString &Session, CAuthorization &Authorization);
            void CheckBearerAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization, COnSocketExecuteEvent && OnContinue);

            void UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &UniqueId, const CString &Action,
                const CString &Payload, const CString &Agent, const CString &Host);

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization, const CString &UniqueId,
                const CString &Action, const CString &Payload, const CString &Agent, const CString &Host);

            void PreSignedFetch(CHTTPServerConnection *AConnection, const CString &UniqueId, const CString &Action,
                const CString &Payload, CSession *ASession);

            void SignedFetch(CHTTPServerConnection *AConnection, const CString &UniqueId, const CString &Action,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow = 60000);

            void Initialization(CModuleProcess *AProcess) override;

            bool Execute(CHTTPServerConnection *AConnection) override;

            void Heartbeat(CDateTime DateTime) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

            void IncProgress() { m_Progress++; }
            void DecProgress() { m_Progress--; }

            int AddToQueue(CObserverHandler *AHandler);
            void InsertToQueue(int Index, CObserverHandler *AHandler);
            void RemoveFromQueue(CObserverHandler *AHandler);

            CQueue &Queue() { return m_Queue; }
            const CQueue &Queue() const { return m_Queue; }

            CPollManager &QueueManager() { return m_QueueManager; }
            const CPollManager &QueueManager() const { return m_QueueManager; }

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_WEBSOCKETAPI_HPP
