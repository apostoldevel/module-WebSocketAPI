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

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CWebSocketAPI ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CWebSocketAPI::CWebSocketAPI(CModuleProcess *AProcess) : CApostolModule(AProcess, "web socket api"),
            m_ObserverDate{0, 0} {

            m_Headers.Add("Authorization");
            m_Headers.Add("Session");
            m_Headers.Add("Secret");

            m_CheckDate = Now();
            gettimeofday(&m_ObserverDate, nullptr);

            m_HeartbeatInterval = 1000;

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

                const auto& session = Payload[_T("session")].AsString();
                const auto& secret = Payload[_T("secret")].AsString();

                pSession->Session() = session;
                pSession->Secret() = secret;

                pSession->Authorized(true);
            };

            auto SignOut = [pSession](const CJSON &Payload) {
                pSession->Session().Clear();
                pSession->Secret().Clear();
                pSession->Authorized(false);
            };

            auto Authorize = [pSession](const CJSON &Payload) {

                if (Payload.HasOwnProperty(_T("authorized"))) {
                    pSession->Authorized(Payload[_T("authorized")].AsBoolean());
                }

                if (!pSession->Authorized()) {
                    pSession->Secret().Clear();
                    pSession->Authorization().Clear();

                    const auto& message = Payload[_T("message")].AsString();
                    throw Delphi::Exception::Exception(message.IsEmpty() ? _T("Unknown error.") : message.c_str());
                }
            };

            if (Path == _T("/api/v1/sign/in")) {
                SignIn(Payload);
            } else if (Path == _T("/api/v1/sign/out")) {
                SignOut(Payload);
            } else if (Path == _T("/api/v1/authenticate")) {
                Authorize(Payload);
            } else if (Path == _T("/api/v1/authorize")) {
                Authorize(Payload);
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

                CHTTPReply::CStatusType status = CHTTPReply::bad_request;

                try {
                    CString jsonString;
                    PQResultToJson(pResult, jsonString, bDataArray);

                    wsmResponse.Payload << jsonString;

                    if (pResult->nTuples() == 1) {
                        wsmResponse.ErrorCode = CheckError(bDataArray ? wsmResponse.Payload[0] : wsmResponse.Payload, wsmResponse.ErrorMessage);
                        if (wsmResponse.ErrorCode == 0) {
                            status = CHTTPReply::unauthorized;
                            AfterQuery(pConnection, caPath, wsmResponse.Payload);
                        } else {
                            wsmResponse.MessageTypeId = mtCallError;
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    wsmResponse.MessageTypeId = mtCallError;
                    wsmResponse.ErrorCode = status;
                    wsmResponse.ErrorMessage = E.what();

                    Log()->Error(APP_LOG_ERR, 0, E.what());
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

        void CWebSocketAPI::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                            .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                            .Format("SELECT * FROM daemon.unauthorized_fetch(%s, %s, %s::jsonb, %s, %s);",
                                    PQQuoteLiteral(Method).c_str(),
                                    PQQuoteLiteral(Path).c_str(),
                                    caPayload.c_str(),
                                    PQQuoteLiteral(Agent).c_str(),
                                    PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Method, const CString &Path, const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Authorization.Token.Size() + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.fetch(%s, %s, %s, %s::jsonb, %s, %s);",
                                        PQQuoteLiteral(Authorization.Token).c_str(),
                                        PQQuoteLiteral(Method).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        caPayload.c_str(),
                                        PQQuoteLiteral(Agent).c_str(),
                                        PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                                .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                                .Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, %s, %s::jsonb, %s, %s);",
                                        Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                        PQQuoteLiteral(Authorization.Username).c_str(),
                                        PQQuoteLiteral(Authorization.Password).c_str(),
                                        PQQuoteLiteral(Method).c_str(),
                                        PQQuoteLiteral(Path).c_str(),
                                        caPayload.c_str(),
                                        PQQuoteLiteral(Agent).c_str(),
                                        PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Method, Path, Payload, Agent, Host);

            }

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::PreSignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, CSession *ASession) {

            CString sData;

            const auto& caNonce = LongToString(MsEpoch() * 1000);

            sData = Path;
            sData << caNonce;
            sData << (Payload.IsEmpty() ? _T("null") : Payload);

            const auto& caSignature = ASession->Secret().IsEmpty() ? _T("") : hmac_sha256(ASession->Secret(), sData);

            SignedFetch(AConnection, Method, Path, Payload, ASession->Session(), caNonce, caSignature, ASession->Agent(), ASession->IP());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::SignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                            .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Session.Size() + Nonce.Size() + Signature.Size() + Agent.Size())
                            .Format("SELECT * FROM daemon.signed_fetch(%s, %s, %s::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
                                    PQQuoteLiteral(Method).c_str(),
                                    PQQuoteLiteral(Path).c_str(),
                                    caPayload.c_str(),
                                    PQQuoteLiteral(Session).c_str(),
                                    PQQuoteLiteral(Nonce).c_str(),
                                    PQQuoteLiteral(Signature).c_str(),
                                    PQQuoteLiteral(Agent).c_str(),
                                    PQQuoteLiteral(Host).c_str(),
                                    ReceiveWindow
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "true");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                DoError(AConnection, CHTTPReply::service_unavailable, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoSessionDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPServerConnection *>(Sender);
            if (pConnection != nullptr) {
                auto pSession = m_SessionManager.FindByConnection(pConnection);
                if (pSession != nullptr) {
                    if (!pConnection->ClosedGracefully()) {
                        Log()->Message(_T("[%s:%d] WebSocket Session %s: Closed connection."),
                                       pConnection->Socket()->Binding()->PeerIP(),
                                       pConnection->Socket()->Binding()->PeerPort(),
                                       pSession->Identity().IsEmpty() ? "(empty)" : pSession->Identity().c_str()
                        );
                    }
                    if (pSession->UpdateCount() == 0) {
                        delete pSession;
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

        void CWebSocketAPI::DoError(const Delphi::Exception::Exception &E) {
            const auto now = Now();
            m_CheckDate = now + (CDateTime) m_HeartbeatInterval * 10 / MSecsPerDay;
            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoCall(CHTTPServerConnection *AConnection, const CString &Action, const CString &Payload) {
            auto pWSReply = AConnection->WSReply();

            CWSMessage wsmMessage;

            wsmMessage.MessageTypeId = mtCall;
            wsmMessage.UniqueId = GetUID(42);
            wsmMessage.Action = Action;
            wsmMessage.Payload << Payload;

            CString sMessage;
            CWSProtocol::Response(wsmMessage, sMessage);

            pWSReply->SetPayload(sMessage);
            AConnection->SendWebSocket(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::DoError(CHTTPServerConnection *AConnection, CHTTPReply::CStatusType Status, const std::exception &e) {
            auto pWSReply = AConnection->WSReply();

            CWSMessage wsmRequest;
            CWSMessage wsmResponse;

            CWSProtocol::PrepareResponse(wsmRequest, wsmResponse);

            wsmResponse.MessageTypeId = mtCallError;
            wsmResponse.ErrorCode = Status;
            wsmResponse.ErrorMessage = e.what();

            CString sResponse;
            CWSProtocol::Response(wsmResponse, sResponse);

            pWSReply->SetPayload(sResponse);
            AConnection->SendWebSocket();

            Log()->Error(APP_LOG_ERR, 0, e.what());
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

            if (cPath[0] != "session") {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            const auto& caIdentity = cPath[1];
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

                    if (wsmRequest.MessageTypeId == mtOpen) {

                        pSession->Session() = pSession->Identity();

                        if (wsmRequest.Payload.HasOwnProperty("secret")) {
                            wsmRequest.Action = _T("/api/v1/authenticate");

                            const auto &session = wsmRequest.Payload[_T("session")].AsString();
                            const auto &secret = wsmRequest.Payload[_T("secret")].AsString();

                            if (!session.IsEmpty() && session != pSession->Session()) // check session value
                                throw Delphi::Exception::Exception(_T("Invalid session value."));

                            if (secret.IsEmpty())
                                throw Delphi::Exception::Exception(_T("Secret cannot be empty."));

                            pSession->Secret() = secret;
                            pSession->Authorization().Clear();
                            pSession->Authorized(false);

                            wsmRequest.Payload.Clear();
                            wsmRequest.Payload.Object().AddPair(_T("session"), pSession->Session());
                            wsmRequest.Payload.Object().AddPair(_T("secret"), pSession->Secret());
                            wsmRequest.Payload.Object().AddPair(_T("agent"), pSession->Agent());
                            wsmRequest.Payload.Object().AddPair(_T("host"), pSession->IP());

                        } else if (wsmRequest.Payload.HasOwnProperty("token")) {
                            wsmRequest.Action = _T("/api/v1/authorize");

                            const auto& token = wsmRequest.Payload[_T("token")].AsString();

                            if (pSession->Identity() != VerifyToken(token))
                                throw Delphi::Exception::Exception(_T("Token from another session."));

                            pSession->Secret().Clear();
                            pSession->Authorization() << "Bearer " + token;
                            pSession->Authorization().TokenType = CAuthorization::attAccess;
                            pSession->Authorized(false);

                            wsmRequest.Payload.Clear();
                            wsmRequest.Payload.Object().AddPair(_T("session"), pSession->Session());
                            wsmRequest.Payload.Object().AddPair(_T("agent"), pSession->Agent());
                            wsmRequest.Payload.Object().AddPair(_T("host"), pSession->IP());
                        }

                        wsmRequest.MessageTypeId = mtCall;
                        UnauthorizedFetch(AConnection, "POST", wsmRequest.Action, wsmRequest.Payload.ToString(), pSession->Agent(), pSession->IP());

                        return;
                    } else if (wsmRequest.MessageTypeId == mtClose) {
                        wsmRequest.Action = _T("/api/v1/sign/out");
                        wsmRequest.MessageTypeId = mtCall;
                    }

                    if (wsmRequest.MessageTypeId == mtCall) {
                        const auto& caAuthorization = pSession->Authorization();

                        if (caAuthorization.Schema == CAuthorization::asBasic && caAuthorization.Username != pSession->Identity()) {
                            throw Delphi::Exception::Exception(_T("Invalid session header value."));
                        }

                        const auto& caPayload = wsmRequest.Payload.ToString();

                        if (wsmRequest.Action.SubString(0, 8) != _T("/api/v1/"))
                            wsmRequest.Action = _T("/api/v1") + wsmRequest.Action;

                        if (caAuthorization.Schema != CAuthorization::asUnknown) {
                            AuthorizedFetch(AConnection, caAuthorization, "POST", wsmRequest.Action, caPayload, pSession->Agent(), pSession->IP());
                        } else {
                            if (pSession->Secret().IsEmpty())
                                throw Delphi::Exception::Exception(_T("Secret cannot be empty."));
                            PreSignedFetch(AConnection, "POST", wsmRequest.Action, caPayload, pSession);
                        }
                    }
                } catch (jwt::token_expired_exception &e) {
                    DoError(AConnection, CHTTPReply::forbidden, e);
                } catch (std::exception &e) {
                    DoError(AConnection, CHTTPReply::bad_request, e);
                }
            } catch (std::exception &e) {
                AConnection->SendWebSocketClose();
                AConnection->CloseConnection(true);

                Log()->Error(APP_LOG_EMERG, 0, e.what());
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

        CString CWebSocketAPI::VerifyToken(const CString &Token) {

            auto decoded = jwt::decode(Token);

            const auto& aud = CString(decoded.get_audience());
            const auto& alg = CString(decoded.get_algorithm());
            const auto& iss = CString(decoded.get_issuer());

            const auto& Providers = Server().Providers();

            CString Application;
            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();
            const auto& Secret = OAuth2::Helper::GetSecret(Provider, Application);

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            if (alg == "HS256") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs256{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS384") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs384{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS512") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs512{Secret});
                verifier.verify(decoded);
            }

            return decoded.get_payload_claim("sub").as_string();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::Observer(CSession *ASession, struct timeval ADate) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                try {
                    auto pResult = APollQuery->Results(0);
                    auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

                    if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                    }

                    if (pResult->nTuples() == 1) {
                        const CJSON Payload(pResult->GetValue(0, 0));
                        CString errorMessage;
                        if (CheckError(Payload, errorMessage) != 0)
                            throw Delphi::Exception::EDBError(errorMessage.c_str());
                    }

                    if (pResult->nTuples() != 0) {
                        CString jsonString;
                        PQResultToJson(pResult, jsonString, true);
                        DoCall(pConnection, "/observer", jsonString);
                    }
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            if (ASession->Authorized()) {

                CStringList SQL;

                SQL.Add(CString().Format("SELECT * FROM daemon.observer('%s', %d.%d, %s, %s);",
                                         ASession->Session().c_str(),
                                         ADate.tv_sec, ADate.tv_usec,
                                         PQQuoteLiteral(ASession->Agent()).c_str(),
                                         PQQuoteLiteral(ASession->IP()).c_str()
                ));

                try {
                    ExecSQL(SQL, ASession->Connection(), OnExecuted, OnException);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CWebSocketAPI::Heartbeat() {
            auto now = Now();

            if (now >= m_CheckDate) {
                struct timeval tv = {0, 0};
                gettimeofday(&tv, nullptr);

                for (int i = 0; i < m_SessionManager.Count(); ++i)
                    Observer(m_SessionManager[i], m_ObserverDate);

                m_ObserverDate = tv;
                m_CheckDate = now + (CDateTime) m_HeartbeatInterval / MSecsPerDay;
            }

            CApostolModule::Heartbeat();
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/WebSocketAPI", "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CWebSocketAPI::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 9) == _T("/session/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}