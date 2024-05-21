use openai_api_rust::{
    chat::{ChatApi, ChatBody}, Auth, Error, Message, OpenAI, Role
};

pub struct SecretsAgent {
    system_prompt: String,
    model: String,
    client: OpenAI,
}

static SYSTEM_PROMPT:&str = r#"
You are an agent dedicated to detect secret keys in the input text by using regex rules.
You are supposed to carefully read the entire text and find out if any part of the input
matches any of the provided regex rules.

The following are the 11 regex rules:
1. Name: Github Personal Access Token , Regex: ghp_[0-9a-zA-Z]{36}
2. Name: npm access token , Regex: (?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)
3. Name: American Express Card , Regex: ^3[47][0-9]{13}$
4. Name: Mastercard, Regex: ^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$
5. Name: VISA Card, Regex: ^4[0-9]{12}(?:[0-9]{3})?$
6. Name: Personal Email, Regex: ([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)
7. Name: IP Address, Regex: (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
8. Name: Phone Number, Regex: ^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$
9. Name: AWS Access Token, Regex: (?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
10. Name: JSON Web token, Regex: \b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:['|\"|\n|\r|\s|\x60|;]|$)
11. Name: JWT Base 64, Regex: \bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}

In case you find multiple inputs that match the regex, send an output in the following format:

Found the following secrets in the given file:
Name: <Comma separated names of all the detected regex rules> ,
Value: <Comma separated values of all the secrets detected using regex>

In case multiple secrets are found, return each one of them according to the instructions shared above

If it is not found, just return the message "No secret keys found"
"#;
impl SecretsAgent {
    pub fn prompt(&self, mut input: String) -> Result<String, Error> {
        input.truncate(16384);
        let body = ChatBody {
            model: self.model.clone(),
            max_tokens: None,
            temperature: Some(0_f32),
            top_p: Some(0_f32),
            n: Some(2),
            stream: Some(false),
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            logit_bias: None,
            user: None,
            messages: vec![
                Message {
                    role: Role::System,
                    content: self.system_prompt.clone(),
                },
                Message {
                    role: Role::User,
                    content: input,
                },
            ],
        };
        let completion = self.client.chat_completion_create(&body)?;
        let choices = completion.choices;
        let message = choices[0].message.as_ref();
        if message.is_none() {
            return Ok(String::from("failed to receive response"));
        }
        return Ok(message.unwrap().content.to_string());
    }
}

pub fn scan_for_secrets(data:String)->String{
    let base_url = std::env::var("BASE_URL").unwrap();
    let auth = Auth::from_env().unwrap();
    let client = OpenAI::new(auth,&base_url);
    let agent = SecretsAgent{
        system_prompt:String::from(SYSTEM_PROMPT),
        model:std::env::var("MODEL").unwrap(),
        client:client
    };
    let res = match agent.prompt(data){
        Ok(data)=>data,
        Err(err)=>{
            println!("{}",err.to_string());
            String::from("failed to detect secrets")
        }
    };
    res
}