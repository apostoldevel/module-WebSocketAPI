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
            int errorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    errorCode = error[_T("code")].AsInteger();
                } else {
                    errorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (errorCode >= 10000)
                    errorCode = errorCode / 100;

                if (errorCode < 0)
                    errorCode = 400;
            }

            return errorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {

            auto pSession = CSession::FindOfConnection(AConnection);

            auto SignIn = [pSession](const CJSON &Payload) {

                const auto& Session = Payload[_T("session")].AsString();
                const auto& Secret = Payload[_T("secret")].AsString();

                pSession->Session() = Session;
                pSession->Secret() = Secret;
            };

            auto SignOut = [pSession](const CJSON &Payload) {
                pSession->Session().Clear();
                pSession->Secret().Clear();
            };

            if (Path == _T("/sign/in")) {

                SignIn(Payload);

            } else if (Path == _T("/sign/out")) {

                SignOut(Payload);

            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {

            auto pResult = APollQuery->Results(0);

            if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError(pResult->GetErrorMessage()));
                return;
            }

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (pConnection != nullptr && pConnection->Connected()) {

                const auto& caPath = pConnection->Data()["path"].Lower();
                const auto bDataArray = caPath.Find(_T("/list")) != CString::npos;

                auto pWSRequest = pConnection->WSRequest();
                auto pWSReply = pConnection->WSReply();

                const CString csRequest(pWSRequest->Payload());

                CWSMessage wsmRequest;
                CWSProtocol::Request(csRequest, wsmRequest);

                CWSMessage wsmResponse;
                CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

                CHTTPReply::CStatusType LStatus = CHTTPReply::bad_request;

                try {
                    CString jsonString;
                    PQResultToJson(pResult, jsonString, bDataArray);

                    wsmResponse.Payload << jsonString;

                    if (pResult->nTuples() == 1) {
                        wsmResponse.ErrorCode = CheckError(wsmResponse.Payload, wsmResponse.ErrorMessage);
                        if (wsmResponse.ErrorCode == 0) {
                            LStatus = CHTTPReply::unauthorized;
                            AfterQuery(pConnection, wsmRequest.Action, wsmResponse.Payload);
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

                CString sResponse;
                CWSProtocol::Response(wsmResponse, sResponse);

                pWSReply->SetPayload(sResponse);
                pConnection->SendWebSocket(true);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (pConnection != nullptr && pConnection->Connected()) {
                auto pWSRequest = pConnection->WSRequest();
                auto pWSReply = pConnection->WSReply();

                const CString csRequest(pWSRequest->Payload());

                CWSMessage wsmRequest;
                CWSProtocol::Request(csRequest, wsmRequest);

                CWSMessage wsmResponse;
                CString sResponse;

                CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

                wsmResponse.MessageTypeId = mtCallError;
                wsmResponse.ErrorCode = CHTTPReply::internal_server_error;
                wsmResponse.ErrorMessage = E.what();

                CWSProtocol::Response(wsmResponse, sResponse);

                pWSReply->SetPayload(sResponse);
                pConnection->SendWebSocket(true);
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

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Authorization.Token.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.fetch(%s, %s, '%s'::jsonb, %s, %s);",
                                        PQQuoteLiteral(Authorization.Token).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        caPayload.c_str(),
                                        PQQuoteLiteral(Agent).c_str(),
                                        PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Path.Size() + caPayload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, '%s'::jsonb, %s, %s);",
                                        Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                        PQQuoteLiteral(Authorization.Username).c_str(),
                                        PQQuoteLiteral(Authorization.Password).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        caPayload.c_str(),
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

            CString sData;

            const auto& caNonce = LongToString(MsEpoch() * 1000);

            sData = Path;
            sData << caNonce;
            sData << (Payload.IsEmpty() ? _T("null") : Payload);

            const auto& caSignature = ASession->Secret().IsEmpty() ? _T("") : hmac_sha256(ASession->Secret(), sData);

            SignedFetch(AConnection, Path, Payload, ASession->Session(), caNonce, caSignature, ASession->Agent(), ASession->IP());
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
            auto pConnection = dynamic_cast<CHTTPServerConnection *>(Sender);
            if (pConnection != nullptr) {
                auto LSession = m_SessionManager.FindByConnection(pConnection);
                if (LSession != nullptr) {
                    if (!pConnection->ClosedGracefully()) {
                        Log()->Message(_T("[%s:%d] WebSocket Session %s: Closed connection."),
                                       pConnection->Socket()->Binding()->PeerIP(),
                                       pConnection->Socket()->Binding()->PeerPort(),
                                       LSession->Identity().IsEmpty() ? "(empty)" : LSession->Identity().c_str()
                        );
                    }
                    if (LSession->UpdateCount() == 0) {
                        delete LSession;
                    }
                } else {
                    if (!pConnection->ClosedGracefully()) {
                        Log()->Message(_T("[%s:%d] Unknown WebSocket Session: Closed connection."),
                                       pConnection->Socket()->Binding()->PeerIP(),
                                       pConnection->Socket()->Binding()->PeerPort()
                        );
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization) {

            const auto &caHeaders = ARequest->Headers;
            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {

                const auto &headerSession = caHeaders.Values(_T("Session"));
                const auto &headerSecret = caHeaders.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << caAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoError(CHTTPServerConnection *AConnection, CHTTPReply::CStatusType Status, Delphi::Exception::Exception &E) {
            auto pWSReply = AConnection->WSReply();

            CWSMessage wsmRequest;
            CWSMessage wsmResponse;

            CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

            wsmResponse.MessageTypeId = mtCallError;
            wsmResponse.ErrorCode = Status;
            wsmResponse.ErrorMessage = E.what();

            CString sResponse;
            CWSProtocol::Response(wsmResponse, sResponse);

            pWSReply->SetPayload(sResponse);
            AConnection->SendWebSocket();

            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoGet(CHTTPServerConnection *AConnection) {

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::html;

            CStringList cPath;
            SplitColumns(pRequest->Location.pathname, cPath, '/');

            if (cPath.Count() != 2) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            const auto& caIdentity = cPath[1].Lower() == _T("api") ? ApostolUID() : cPath[1];

            const auto& caSecWebSocketKey = pRequest->Headers.Values(_T("Sec-WebSocket-Key"));
            const auto& caSecWebSocketProtocol = pRequest->Headers.Values(_T("Sec-WebSocket-Protocol"));

            if (caSecWebSocketKey.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            const CString csAccept(SHA1(caSecWebSocketKey + _T("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            const CString csProtocol(caSecWebSocketProtocol.IsEmpty() ? "" : caSecWebSocketProtocol.SubString(0, caSecWebSocketProtocol.Find(',')));

            AConnection->SwitchingProtocols(csAccept, csProtocol);

            auto pSession = m_SessionManager.FindByIdentity(caIdentity);

            if (pSession == nullptr) {
                pSession = m_SessionManager.Add(AConnection);
                pSession->Identity() = caIdentity;
            } else {
                pSession->SwitchConnection(AConnection);
            }

            pSession->IP() = GetHost(AConnection);
            pSession->Agent() = GetUserAgent(AConnection);

            CheckAuthorizationData(pRequest, pSession->Authorization());

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            AConnection->OnDisconnected([this](auto && Sender) { DoSessionDisconnected(Sender); });
#else
            AConnection->OnDisconnected(std::bind(&CWebSocketAPI::DoSessionDisconnected, this, _1));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoWebSocket(CHTTPServerConnection *AConnection) {

            auto pWSRequest = AConnection->WSRequest();

            const CString csRequest(pWSRequest->Payload());

            try {
                if (!AConnection->Connected())
                    return;

                auto pSession = CSession::FindOfConnection(AConnection);

                try {
                    CWSMessage wsmRequest;
                    CWSMessage wsmResponse;

                    CWSProtocol::Request(csRequest, wsmRequest);

                    const auto &caAuthorization = pSession->Authorization();

                    if (wsmRequest.MessageTypeId == mtOpen) {
                        if (wsmRequest.Payload.ValueType() == jvtObject) {
                            wsmRequest.Action = _T("/authorize");

                            pSession->Session() = wsmRequest.Payload[_T("session")].AsString();
                            pSession->Secret() = wsmRequest.Payload[_T("secret")].AsString();

                            if (pSession->Session().IsEmpty() || pSession->Secret().IsEmpty())
                                throw Delphi::Exception::Exception(_T("Session or secret cannot be empty."));

                            wsmRequest.Payload -= _T("secret");
                        } else {
                            if (caAuthorization.Schema == CAuthorization::asBasic) {
                                wsmRequest.Action = _T("/sign/in");
                                wsmRequest.Payload.Object().AddPair(_T("username"), pSession->Authorization().Username);
                                wsmRequest.Payload.Object().AddPair(_T("password"), pSession->Authorization().Password);
                            }
                        }

                        wsmRequest.MessageTypeId = mtCall;
                    } else if (wsmRequest.MessageTypeId == mtClose) {
                        wsmRequest.Action = _T("/sign/out");
                        wsmRequest.MessageTypeId = mtCall;
                    }

                    if (wsmRequest.MessageTypeId == mtCall) {
                        const auto& caPayload = wsmRequest.Payload.ToString();
                        if (caAuthorization.Schema != CAuthorization::asUnknown) {
                            AuthorizedFetch(AConnection, caAuthorization, wsmRequest.Action, caPayload, pSession->Agent(), pSession->IP());
                        } else {
                            PreSignedFetch(AConnection, wsmRequest.Action, caPayload, pSession);
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