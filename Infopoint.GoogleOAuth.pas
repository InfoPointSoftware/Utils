unit Infopoint.GoogleOAuth;

interface

uses
   Classes,
   SysUtils,
   DateUtils,
   Winapi.ShellAPI,
   IdHTTPServer,
   IdURI,
   IdContext,
   IdCustomHTTPServer,
   IdSASL,
   REST.Authenticator.OAuth,
   REST.Client,
   REST.Types,
   IPPeerClient,
   System.Types;

type
   TEnhancedOAuth2Authenticator = class(TOAuth2Authenticator)
   private
      procedure RequestNewAcessToken;
   end;

   TOnToken = procedure(const pAcessToken, pRefreshToken: string; const pDataExpiracao: TDateTime) of object;

   TGMailOAuth = class
   private
      fOAuth2: TEnhancedOAuth2Authenticator;
      fHTTPServer: TIdHTTPServer;
      fOnToken: TOnToken;
      procedure OnHTTPServerCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
   public
      constructor Create(const pClientId, pClientSecret, pAccessToken, pRefreshToken: string; const pTokenExpiry: TDateTime;
         const pOnToken: TOnToken; const pRedirectionEndpoint: string = ''); reintroduce;
      destructor Destroy; override;

      function Authenticate(const OpenUrl: Boolean = true): string;
      function RefreshNewToken: Boolean;
      function getAccessToken: string;
      function getTokenExpiry: TDateTime;
      procedure ChangeAuthCode(const Code: string);

   end;

implementation

uses
   REST.Utils;

{ TGmailAOuth }

procedure TGMailOAuth.ChangeAuthCode(const Code: string);
begin
   fOAuth2.AuthCode := Code;
   fOAuth2.ChangeAuthCodeToAccesToken;

   fOnToken(fOAuth2.AccessToken, fOAuth2.RefreshToken, fOAuth2.AccessTokenExpiry);
end;

constructor TGMailOAuth.Create(const pClientId, pClientSecret, pAccessToken, pRefreshToken: string;
   const pTokenExpiry: TDateTime; const pOnToken: TOnToken; const pRedirectionEndpoint: string);
begin
   inherited Create;
   fOAuth2 := TEnhancedOAuth2Authenticator.Create(nil);

   fOAuth2.ClientID := pClientId;
   fOAuth2.ClientSecret := pClientSecret;
   fOAuth2.AccessToken := pAccessToken;
   fOAuth2.RefreshToken := pRefreshToken;
   fOnToken := pOnToken;
   fOAuth2.Scope := 'https://mail.google.com/ openid';
   fOAuth2.RedirectionEndpoint := pRedirectionEndpoint;
   fOAuth2.AuthorizationEndpoint := 'https://accounts.google.com/o/oauth2/auth';
   fOAuth2.AccessTokenEndpoint := 'https://accounts.google.com/o/oauth2/token';

   if fOAuth2.RedirectionEndpoint = EmptyStr then
      fOAuth2.RedirectionEndpoint := 'http://localhost:3000';

   {$IFDEF VER260}
   fOAuth2.SetAccessTokenExpiry(pTokenExpiry);
   {$ELSE}
   fOAuth2.AccessTokenExpiry := pTokenExpiry;
   {$ENDIF}

   fHTTPServer := TIdHTTPServer.Create(nil);
   fHTTPServer.OnCommandGet := OnHTTPServerCommandGet;
   fHTTPServer.DefaultPort := 3000;
end;

destructor TGMailOAuth.Destroy;
begin
   fOAuth2.free;
   fHTTPServer.free;
   inherited Destroy;
end;

function TGMailOAuth.Authenticate(const OpenUrl: Boolean): string;
var
   uri: TIdURI;
begin
   Result := fOAuth2.AuthorizationRequestURI + '&access_type=offline';

   if fOAuth2.AccessToken = '' then
      if OpenUrl then
      begin
         fHTTPServer.Active := True;
         uri := TidURI.Create(Result);
         try
            ShellExecute(0, 'open', PChar(uri.GetFullURI), nil, nil, 0);
         finally
            uri.Free;
         end;
      end;
end;

function TGMailOAuth.getAccessToken: string;
begin
   Result := fOAuth2.AccessToken;
end;

function TGMailOAuth.getTokenExpiry: TDateTime;
begin
   Result := fOAuth2.AccessTokenExpiry;
end;

procedure TGMailOAuth.OnHTTPServerCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
   code, msg: string;
   uri: TIdURI;
begin
   msg := 'Ocorreu um problema na autenticação no serviço de e-mail.';

   if ARequestInfo.QueryParams = '' then
      Exit;

   uri := TIdURI.Create(fOAuth2.RedirectionEndpoint + '/?' + ARequestInfo.QueryParams);
   try
      try
         code := ARequestInfo.Params.Values['code'];

         ChangeAuthCode(code);
         msg := 'Autenticação realizada com sucesso.';
      except
         Exit;
      end;

      AResponseInfo.ContentText := Format('<!DOCTYPE html><html lang="en"><head><title>Autenticação</title>' +
         '</head><body><h2>%s</h2></body></html>', [msg]);
   finally
      uri.Free;
   end;
end;

function TGMailOAuth.RefreshNewToken: Boolean;
begin
   Result := False;
   if CompareTime(fOAuth2.AccessTokenExpiry, now) = LessThanValue then
   begin
      fOAuth2.RequestNewAcessToken;
      Result := True;
   end;
end;

{ TEnhancedOAuth2Authenticator }

procedure TEnhancedOAuth2Authenticator.RequestNewAcessToken;
var
   LClient: TRestClient;
   LRequest: TRESTRequest;
   LToken: string;
   LIntValue: int64;
begin
   if ClientID = '' then
      raise TOAuth2Exception.Create('Client ID vazio.');

   if RefreshToken = '' then
      raise TOAuth2Exception.Create('Token vazio.');

   LClient := TRestClient.Create(AccessTokenEndpoint);
   LRequest := TRESTRequest.Create(LClient);
   try
      LRequest.Method := TRESTRequestMethod.rmPOST;
      LRequest.AddAuthParameter('refresh_token', RefreshToken, TRESTRequestParameterKind.pkGETorPOST);
      LRequest.AddAuthParameter('client_id', ClientID, TRESTRequestParameterKind.pkGETorPOST);
      LRequest.AddAuthParameter('client_secret', ClientSecret, TRESTRequestParameterKind.pkGETorPOST);
      LRequest.AddAuthParameter('grant_type', 'refresh_token', TRESTRequestParameterKind.pkGETorPOST);

      LRequest.Execute;

      if LRequest.Response.GetSimpleValue('access_token', LToken) then
         AccessToken := LToken;
      if LRequest.Response.GetSimpleValue('refresh_token', LToken) then
         RefreshToken := LToken;

      if LRequest.Response.GetSimpleValue('token_type', LToken) then
         TokenType := OAuth2TokenTypeFromString(LToken);

      if LRequest.Response.GetSimpleValue('expires_in', LToken) then
      begin
         LIntValue := StrToIntdef(LToken, -1);
         if (LIntValue > -1) then
            AccessTokenExpiry := IncSecond(Now, LIntValue)
         else
            AccessTokenExpiry := 0.0;
      end;

      if (AccessToken <> '') then
      begin
         AuthCode := '';
      end;
   finally
      FreeAndNil(LClient);
   end;
end;

end.

