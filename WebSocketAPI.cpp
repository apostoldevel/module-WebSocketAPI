/*++

Program name:

  Apostol Web Service

Module Name:

  WebSocketAPI.cpp

Notices:

  Module: Web Socket API

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "WebSocketAPI.hpp"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CWebSocketAPI ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CWebSocketAPI::CWebSocketAPI(CModuleProcess *AProcess) : CApostolModule(AProcess, "web socket api") {
            m_Headers.Add("Authorization");
            m_Headers.Add("Session");
            m_Headers.Add("Secret");

            m_FixedDate = Now();

            CWebSocketAPI::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CWebSocketAPI::DoGet, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CWebSocketAPI::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        int CWebSocketAPI::CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (ErrorCode >= 10000)
                    ErrorCode = ErrorCode / 100;
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {

            auto LSession = CSession::FindOfConnection(AConnection);

            auto SignIn = [LSession](const CJSON &Payload) {

                const auto& Session = Payload[_T("session")].AsString();
                const auto& Secret = Payload[_T("secret")].AsString();

                LSession->Session() = Session;
                LSession->Secret() = Secret;
            };

            auto SignOut = [LSession](const CJSON &Payload) {
                LSession->Session().Clear();
                LSession->Secret().Clear();
            };

            if (Path == _T("/sign/in")) {

                SignIn(Payload);

            } else if (Path == _T("/sign/out")) {

                SignOut(Payload);

            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {
            clock_t start = clock();

            auto LResult = APollQuery->Results(0);

            if (LResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError(LResult->GetErrorMessage()));
                return;
            }

            CString ErrorMessage;

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection != nullptr && LConnection->Connected()) {

                const auto& Path = LConnection->Data()["path"].Lower();
                const auto DataArray = Path.Find(_T("/list")) != CString::npos;

                auto LWSRequest = LConnection->WSRequest();
                auto LWSReply = LConnection->WSReply();

                const CString LRequest(LWSRequest->Payload());

                CWSMessage wsmRequest;
                CWSProtocol::Request(LRequest, wsmRequest);

                CWSMessage wsmResponse;
                CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

                CReply::CStatusType LStatus = CReply::bad_request;

                try {
                    CString jsonString;
                    PQResultToJson(LResult, jsonString, DataArray);

                    wsmResponse.Payload << jsonString;

                    if (LResult->nTuples() == 1) {
                        wsmResponse.ErrorCode = CheckError(wsmResponse.Payload, wsmResponse.ErrorMessage);
                        if (wsmResponse.ErrorCode == 0) {
                            LStatus = CReply::unauthorized;
                            AfterQuery(LConnection, wsmRequest.Action, wsmResponse.Payload);
                        } else {
                            wsmResponse.MessageTypeId = mtCallError;
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    wsmResponse.MessageTypeId = mtCallError;
                    wsmResponse.ErrorCode = LStatus;
                    wsmResponse.ErrorMessage = E.what();

                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                CString LResponse;
                CWSProtocol::Response(wsmResponse, LResponse);

                LWSReply->SetPayload(LResponse);
                LConnection->SendWebSocket(true);
            }

            log_debug1(APP_LOG_DEBUG_CORE, Log(), 0, _T("Query executed runtime: %.2f ms."), (double) ((clock() - start) / (double) CLOCKS_PER_SEC * 1000));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::QueryException(CPQPollQuery *APollQuery, const std::exception &e) {

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection != nullptr && LConnection->Connected()) {
                auto LWSRequest = LConnection->WSRequest();
                auto LWSReply = LConnection->WSReply();

                const CString LRequest(LWSRequest->Payload());

                CWSMessage wsmRequest;
                CWSProtocol::Request(LRequest, wsmRequest);

                CWSMessage wsmResponse;
                CString LResponse;

                CJSON LJson;

                CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

                wsmResponse.MessageTypeId = mtCallError;
                wsmResponse.ErrorCode = CReply::internal_server_error;
                wsmResponse.ErrorMessage = e.what();

                CWSProtocol::Response(wsmResponse, LResponse);

                LWSReply->SetPayload(LResponse);
                LConnection->SendWebSocket(true);
            }

            Log()->Error(APP_LOG_EMERG, 0, e.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoPostgresQueryException(CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {
            QueryException(APollQuery, *AException);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                                            const CString &Agent, const CString &Host) {

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.unauthorized_fetch(%s, '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Path).c_str(),
                                     Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                                          const CString &Path, const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                SQL.Add(CString().Format("SELECT * FROM daemon.fetch(%s, %s, '%s'::jsonb, %s, %s);",
                                         PQQuoteLiteral(Authorization.Token).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                SQL.Add(CString().Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, '%s'::jsonb, %s, %s);",
                                         Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                         PQQuoteLiteral(Authorization.Username).c_str(),
                                         PQQuoteLiteral(Authorization.Password).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Path, Payload, Agent, Host);

            }

            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::SignedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                                      const CString &Session, const CString &Nonce, const CString &Signature, const CString &Agent,
                                      const CString &Host, long int ReceiveWindow) {

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.signed_fetch(%s, '%s'::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
                                     PQQuoteLiteral(Path).c_str(),
                                     Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                     PQQuoteLiteral(Session).c_str(),
                                     PQQuoteLiteral(Nonce).c_str(),
                                     PQQuoteLiteral(Signature).c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str(),
                                     ReceiveWindow
            ));

            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "true");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoSessionDisconnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CHTTPServerConnection *>(Sender);
            if (LConnection != nullptr) {
                auto LSession = m_SessionManager.FindByConnection(LConnection);
                if (LSession != nullptr) {
                    if (!LConnection->ClosedGracefully()) {
                        Log()->Message(_T("[%s:%d] WebSocket Session %s: Closed connection."),
                                       LConnection->Socket()->Binding()->PeerIP(),
                                       LConnection->Socket()->Binding()->PeerPort(),
                                       LSession->Identity().IsEmpty() ? "(empty)" : LSession->Identity().c_str()
                        );
                    }
                    if (LSession->UpdateCount() == 0) {
                        delete LSession;
                    }
                } else {
                    if (!LConnection->ClosedGracefully()) {
                        Log()->Message(_T("[%s:%d] Unknown WebSocket Session: Closed connection."),
                                       LConnection->Socket()->Binding()->PeerIP(),
                                       LConnection->Socket()->Binding()->PeerPort()
                        );
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::ReplyError(CHTTPServerConnection *AConnection, CReply::CStatusType ErrorCode, const CString &Message) {
            auto LReply = AConnection->Reply();

            if (ErrorCode == CReply::unauthorized) {
                CReply::AddUnauthorized(LReply, AConnection->Data()["Authorization"] != "Basic", "invalid_client", Message.c_str());
            }

            LReply->Content.Clear();
            LReply->Content.Format(R"({"error": {"code": %u, "message": "%s"}})", ErrorCode, Delphi::Json::EncodeJsonString(Message).c_str());

            AConnection->SendReply(ErrorCode, nullptr, true);
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::CheckAuthorizationData(CRequest *ARequest, CAuthorization &Authorization) {

            const auto &LHeaders = ARequest->Headers;
            const auto &LCookies = ARequest->Cookies;

            const auto &LAuthorization = LHeaders.Values(_T("Authorization"));

            if (LAuthorization.IsEmpty()) {

                const auto &headerSession = LHeaders.Values(_T("Session"));
                const auto &headerSecret = LHeaders.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << LAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoGet(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::html;

            CStringList LPath;
            SplitColumns(LRequest->Location.pathname, LPath, '/');

            if (LPath.Count() < 2) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            const auto& LSecWebSocketKey = LRequest->Headers.Values(_T("Sec-WebSocket-Key"));
            if (LSecWebSocketKey.IsEmpty()) {
                AConnection->SendStockReply(CReply::bad_request, true);
                return;
            }

            const auto& LIdentity = LPath[1];
            const auto& LSecWebSocketProtocol = LRequest->Headers.Values(_T("Sec-WebSocket-Protocol"));

            const CString LAccept(SHA1(LSecWebSocketKey + _T("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            const CString LProtocol(LSecWebSocketProtocol.IsEmpty() ? "" : LSecWebSocketProtocol.SubString(0, LSecWebSocketProtocol.Find(',')));

            AConnection->SwitchingProtocols(LAccept, LProtocol);

            auto LSession = m_SessionManager.FindByIdentity(LIdentity);

            if (LSession == nullptr) {
                LSession = m_SessionManager.Add(AConnection);
                LSession->Identity() = LIdentity;
            } else {
                LSession->SwitchConnection(AConnection);
            }

            LSession->IP() = GetHost(AConnection);
            LSession->Agent() = GetUserAgent(AConnection);

            CheckAuthorizationData(LRequest, LSession->Authorization());

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            AConnection->OnDisconnected([this](auto && Sender) { DoSessionDisconnected(Sender); });
#else
            AConnection->OnDisconnected(std::bind(&CWebSocketAPI::DoSessionDisconnected, this, _1));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoWebSocket(CHTTPServerConnection *AConnection) {

            auto LWSRequest = AConnection->WSRequest();
            auto LWSReply = AConnection->WSReply();

            const CString LRequest(LWSRequest->Payload());

            try {
                if (!AConnection->Connected())
                    return;

                auto LSession = CSession::FindOfConnection(AConnection);

                CWSMessage wsmRequest;
                CWSMessage wsmResponse;

                try {
                    CString sigData;

                    CWSProtocol::Request(LRequest, wsmRequest);

                    const auto &LAuthorization = LSession->Authorization();

                    if (wsmRequest.MessageTypeId == mtOpen) {
                        if (wsmRequest.Payload.ValueType() == jvtObject) {
                            wsmRequest.Action = _T("/authorize");

                            LSession->Session() = wsmRequest.Payload[_T("session")].AsString();
                            LSession->Secret() = wsmRequest.Payload[_T("secret")].AsString();

                            if (LSession->Session().IsEmpty() || LSession->Secret().IsEmpty())
                                throw Delphi::Exception::Exception(_T("Session or secret cannot be empty."));

                            wsmRequest.Payload -= _T("secret");
                        } else {
                            if (LAuthorization.Schema == CAuthorization::asBasic) {
                                wsmRequest.Action = _T("/sign/in");
                                wsmRequest.Payload.Object().AddPair(_T("username"), LSession->Authorization().Username);
                                wsmRequest.Payload.Object().AddPair(_T("password"), LSession->Authorization().Password);
                            }
                        }

                        wsmRequest.MessageTypeId = mtCall;
                    } else if (wsmRequest.MessageTypeId == mtClose) {
                        wsmRequest.Action = _T("/sign/out");
                        wsmRequest.MessageTypeId = mtCall;
                    }

                    if (wsmRequest.MessageTypeId == mtCall) {

                        sigData = wsmRequest.Action;

                        const auto& LPayload = wsmRequest.Payload.ToString();

                        if (LAuthorization.Schema != CAuthorization::asUnknown) {
                            AuthorizedFetch(AConnection, LAuthorization, wsmRequest.Action, LPayload, LSession->Agent(), LSession->IP());
                        } else {
                            const auto& LNonce = LongToString(MsEpoch() * 1000);

                            sigData << LNonce;
                            sigData << (LPayload.IsEmpty() ? _T("null") : LPayload);

                            const auto& LSignature = LSession->Secret().IsEmpty() ? _T("") : hmac_sha256(LSession->Secret(), sigData);

                            SignedFetch(AConnection, wsmRequest.Action, LPayload, LSession->Session(), LNonce, LSignature, LSession->Agent(), LSession->IP());
                        }
                    }
                } catch (std::exception &e) {
                    CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

                    wsmResponse.MessageTypeId = mtCallError;
                    wsmResponse.ErrorCode = CReply::bad_request;
                    wsmResponse.ErrorMessage = e.what();

                    CString LResponse;
                    CWSProtocol::Response(wsmResponse, LResponse);

                    LWSReply->SetPayload(LResponse);
                    AConnection->SendWebSocket();

                    Log()->Error(APP_LOG_EMERG, 0, e.what());
                }
            } catch (std::exception &e) {
                AConnection->SendWebSocketClose();
                AConnection->CloseConnection(true);

                Log()->Error(APP_LOG_EMERG, 0, e.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::Execute(CHTTPServerConnection *AConnection) {
            switch (AConnection->Protocol()) {
                case pHTTP:
                    CApostolModule::Execute(AConnection);
                    break;
                case pWebSocket:
#ifdef _DEBUG
                    WSDebugConnection(AConnection);
#endif
                    DoWebSocket(AConnection);
                    break;
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/WebSocketAPI", "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::CheckConnection(CHTTPServerConnection *AConnection) {
            const auto& Location = AConnection->Request()->Location;
            return Location.pathname.SubString(0, 9) == _T("/session/") || AConnection->Protocol() == pWebSocket;
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}