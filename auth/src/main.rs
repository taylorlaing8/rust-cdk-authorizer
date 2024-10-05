use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse, IamPolicyStatement
};
use aws_sdk_ssm::Client;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Validation};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Number};

static POLICY_VERSION: &str = "2012-10-17";

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Effect::Allow => write!(f, "allow"),
            Effect::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationConfig {
    jwks_uri: String,
	issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    iat: Number,
    exp: Number,
    azp: Option<String>,
    scope: Option<String>,
    permissions: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .json()
        .init();

    let shared_config = aws_config::load_from_env().await;
	let client = Client::new(&shared_config);

	let ssm_response = client.get_parameter().name("/authorizer/config").with_decryption(true).send().await?;
	let parameter = ssm_response.parameter().unwrap().value().unwrap();

	let authorizer_config: AuthorizationConfig = serde_json::from_str(parameter).unwrap();	
	
	let jwks_list: jwk::JwkSet = reqwest::get(&authorizer_config.jwks_uri).await?.json::<JwkSet>().await?;
    let valid_issuers_array: [&str; 1] = [authorizer_config.issuer.as_str(); 1];

    lambda_runtime::run(service_fn(
        |event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>| {
            function_handler(&jwks_list, valid_issuers_array, event)
        },
    )).await?;

    Ok(())
}

pub async fn function_handler(
    jwks_list: &JwkSet,
    valid_issuers_array: [&str; 1],
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let method_arn = event.payload.method_arn.unwrap_or_default();
    let request_raw_token = event.payload.headers.get("authorization").unwrap();
    let identity = event.payload.request_context.identity.unwrap_or_default();
    let jwt_token;

    info!("apiid: {}, httpMethod: {}, sourceIp: {}, path: {}, resourceId: {}, resourcePath: {}, requestId: {}, stage: {}, invokedFunctionArn: {}, xrayTraceId: {}",
		event.payload.request_context.apiid.unwrap_or_default(),
		event.payload.request_context.http_method.unwrap_or_default(),
		identity.source_ip.unwrap_or_default(),
		event.payload.request_context.path.unwrap_or_default(),
		event.payload.request_context.resource_id.unwrap_or_default(),
		event.payload.request_context.resource_path.unwrap_or_default(),
		event.payload.request_context.request_id.unwrap_or_default(),
		event.payload.request_context.stage.unwrap_or_default(),
		event.context.invoked_function_arn,
		event.context.xray_trace_id.unwrap_or_default()
	);

    let token = request_raw_token.to_str();

    let token_string = match token {
        Ok(token) => token,
        Err(_e) => {
            debug!("Error decoding header");
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": "Unauthorized" }),
            ));
        }
    };

    let parsed_token: Vec<&str> = token_string.split(" ").collect();

    match parsed_token[0] {
        "Bearer" => {
            jwt_token = parsed_token[1];
        }
        _ => {
            debug!("Invalid Token Type (Not Bearer)");
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": "Unauthorized" }),
            ));
        }
    }

    let header = match decode_header(jwt_token) {
        Ok(header) => header,
        Err(e) => {
            debug!("Error decoding header");
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": &format!("Unauthorized: {}", e) }),
            ));
        }
    };

    let kid = match header.kid {
        Some(k) => k,
        None => {
            debug!("Token doesn't have a `kid` header field");
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": "Unauthorized" }),
            ));
        }
    };

    let jwk = match find_kid_in_key_list(&kid, &jwks_list) {
        Ok(jwk) => jwk,
        Err(e) => {
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": &format!("Unauthorized: {}", e) }),
            ));
        }
    };

    let (decoding_key, algorithm) = match get_decode_key_and_algorithm(jwk) {
        Ok((decoding_key, algorithm)) => (decoding_key, algorithm),
        Err(e) => {
            return Ok(get_authorizer_response(
                &"DENY",
                "",
                &method_arn,
                json!({ "errorMessage": &format!("Unauthorized: {}", e) }),
            ));
        }
    };

    let verified_claims =
        match decode_and_validate_token(jwt_token, decoding_key, algorithm, valid_issuers_array) {
            Ok(verified_claims) => verified_claims,
            Err(e) => {
                return Ok(get_authorizer_response(
                    &"DENY",
                    "",
                    &method_arn,
                    json!({ "errorMessage": &format!("Unauthorized: {}", e) }),
                ));
            }
        };

    let principal_id = &verified_claims.sub;
	let permissions_string = match serde_json::to_string(&verified_claims.permissions) {
		Ok(permissions) => permissions,
		Err(e) => {
			return Ok(get_authorizer_response(
				&"DENY",
				"",
				&method_arn,
				json!({ "errorMessage": &format!("Unauthorized: {}", e) }),
			));
		}
	};

    Ok(get_authorizer_response(
        "ALLOW",
        &principal_id,
        &method_arn,
        json!({ "permissions": permissions_string }),
    ))
}

fn get_decode_key_and_algorithm(jwk: Jwk) -> Result<(DecodingKey, Algorithm), Error> {
    match jwk.algorithm {
        AlgorithmParameters::RSA(ref rsa) => {
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();

            return Ok((decoding_key, jwk.common.algorithm.unwrap()));
        }
        _ => unreachable!("RSA encoding required"),
    }
}

fn find_kid_in_key_list(kid: &str, jwk_list: &JwkSet) -> Result<Jwk, Error> {
    if let Some(j) = jwk_list.find(kid) {
        return Ok(j.clone());
    } else {
        return Err(Box::new(simple_error::SimpleError::new(
            "No matching JWK found for the given kid",
        )));
    }
}

fn decode_and_validate_token(
    jwt_token: &str,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    valid_issuers_array: [&str; 1],
) -> Result<Claims, Error> {
    let mut validation = Validation::new(algorithm);

    validation.validate_exp = true;
    validation.set_issuer(&valid_issuers_array);

    let decoded_token = decode::<Claims>(jwt_token, &decoding_key, &validation)?;

    return Ok(decoded_token.claims);
}

fn get_authorizer_response(
    effect: &str,
    principal_id: &str,
    method_arn: &str,
    context: serde_json::Value,
) -> ApiGatewayCustomAuthorizerResponse {
    let stmt = IamPolicyStatement {
        action: vec!["execute-api:Invoke".to_string()],
        resource: vec![method_arn.to_owned()],
        effect: Some(effect.to_owned()),
    };

    let policy = ApiGatewayCustomAuthorizerPolicy {
        version: Some(POLICY_VERSION.to_string()),
        statement: vec![stmt],
    };

    ApiGatewayCustomAuthorizerResponse {
        principal_id: Some(principal_id.to_owned()),
        policy_document: policy,
        context,
		usage_identifier_key: None
    }
}
