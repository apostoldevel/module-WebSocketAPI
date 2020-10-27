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

                if (ErrorCode < 0)
                    ErrorCode = 400;
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

                CHTTPReply::CStatusType LStatus = CHTTPReply::bad_request;

                try {
                    CString jsonString;
                    PQResultToJson(LResult, jsonString, DataArray);

                    wsmResponse.Payload << jsonString;

                    if (LResult->nTuples() == 1) {
                        wsmResponse.ErrorCode = CheckError(wsmResponse.Payload, wsmResponse.ErrorMessage);
                        if (wsmResponse.ErrorCode == 0) {
                            LStatus = CHTTPReply::unauthorized;
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

            log_debug1(APP_LOG_DEBUG_CORE, Log(), 0, _T("Query executed runtime: %.3f sec."), (double) (clock() - start) / (double) CLOCKS_PER_SEC);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {

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
                wsmResponse.ErrorCode = CHTTPReply::internal_server_error;
                wsmResponse.ErrorMessage = E.what();

                CWSProtocol::Response(wsmResponse, LResponse);

                LWSReply->SetPayload(LResponse);
                LConnection->SendWebSocket(true);
            }

            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            const auto &payload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                            .MaxFormatSize(256 + Path.Size() + payload.Size() + Agent.Size())
                            .Format("SELECT * FROM daemon.unauthorized_fetch(%s, '%s'::jsonb, %s, %s);",
                                    PQQuoteLiteral(Path).c_str(),
                                    payload.c_str(),
                                    PQQuoteLiteral(Agent).c_str(),
                                    PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            try {
                StartQuery(AConnection, SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Path, const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                const auto &payload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Authorization.Token.Size() + Path.Size() + payload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.fetch(%s, %s, '%s'::jsonb, %s, %s);",
                                        PQQuoteLiteral(Authorization.Token).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        payload.c_str(),
                                        PQQuoteLiteral(Agent).c_str(),
                                        PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                const auto &payload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Path.Size() + payload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, '%s'::jsonb, %s, %s);",
                                        Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                        PQQuoteLiteral(Authorization.Username).c_str(),
                                        PQQuoteLiteral(Authorization.Password).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        payload.c_str(),
                                        PQQuoteLiteral(Agent).c_str(),
                                        PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Path, Payload, Agent, Host);

            }

            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            try {
                StartQuery(AConnection, SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::PreSignedFetch(CHTTPServerConnection *AConnection, const CString &Path,
                const CString &Payload, CSession *ASession) {

            CString LData;

            const auto& LNonce = LongToString(MsEpoch() * 1000);

            LData = Path;
            LData << LNonce;
            LData << (Payload.IsEmpty() ? _T("null") : Payload);

            const auto& LSignature = ASession->Secret().IsEmpty() ? _T("") : hmac_sha256(ASession->Secret(), LData);

            SignedFetch(AConnection, Path, Payload, ASession->Session(), LNonce, LSignature, ASession->Agent(), ASession->IP());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::SignedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow) {

            CStringList SQL;

            SQL.Add(CString()
                            .MaxFormatSize(256 + Path.Size() + Payload.Size() + Session.Size() + Nonce.Size() + Signature.Size() + Agent.Size())
                            .Format("SELECT * FROM daemon.signed_fetch(%s, '%s'::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
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

            try {
                StartQuery(AConnection, SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
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

        bool CWebSocketAPI::CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization) {

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

        void CWebSocketAPI::DoError(CHTTPServerConnection *AConnection, CHTTPReply::CStatusType Status, Delphi::Exception::Exception &E) {
            auto LWSReply = AConnection->WSReply();

            CWSMessage wsmRequest;
            CWSMessage wsmResponse;

            CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

            wsmResponse.MessageTypeId = mtCallError;
            wsmResponse.ErrorCode = Status;
            wsmResponse.ErrorMessage = E.what();

            CString LResponse;
            CWSProtocol::Response(wsmResponse, LResponse);

            LWSReply->SetPayload(LResponse);
            AConnection->SendWebSocket();

            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoGet(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CHTTPReply::html;

            CStringList LPath;
            SplitColumns(LRequest->Location.pathname, LPath, '/');

            if (LPath.Count() != 2) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            const auto& LIdentity = LPath[1].Lower() == _T("api") ? ApostolUID() : LPath[1];

            const auto& LSecWebSocketKey = LRequest->Headers.Values(_T("Sec-WebSocket-Key"));
            const auto& LSecWebSocketProtocol = LRequest->Headers.Values(_T("Sec-WebSocket-Protocol"));

            if (LSecWebSocketKey.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

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

            const CString LRequest(LWSRequest->Payload());

            try {
                if (!AConnection->Connected())
                    return;

                auto LSession = CSession::FindOfConnection(AConnection);

                try {
                    CWSMessage wsmRequest;
                    CWSMessage wsmResponse;

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
                        const auto& LPayload = wsmRequest.Payload.ToString();
                        if (LAuthorization.Schema != CAuthorization::asUnknown) {
                            AuthorizedFetch(AConnection, LAuthorization, wsmRequest.Action, LPayload, LSession->Agent(), LSession->IP());
                        } else {
                            PreSignedFetch(AConnection, wsmRequest.Action, LPayload, LSession);
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    DoError(AConnection, CHTTPReply::bad_request, E);
                }
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendWebSocketClose();
                AConnection->CloseConnection(true);

                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::Execute(CHTTPServerConnection *AConnection) {
            if (AConnection->Protocol() == pWebSocket) {
#ifdef _DEBUG
                WSDebugConnection(AConnection);
#endif
                DoWebSocket(AConnection);

                return true;
            } else {
                return CApostolModule::Execute(AConnection);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/WebSocketAPI", "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::CheckLocation(const CLocation &Location) {
            return Location.pathname == _T("/ws/api") || Location.pathname.SubString(0, 9) == _T("/session/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}