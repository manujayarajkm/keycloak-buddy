require('dotenv').config()
const axios= require('axios');
const querystring = require('querystring');

const {CLIENT_ID,CLIENT_SECRET,KEYCLOAK_DOMAIN,REALM_NAME}= process.env;




const processRequest=async(config)=>{
    try {
        const response= await axios(config);
        if(response && response.data){
            return response.data;
        }
        return {};
    } catch (error) {
        console.error('Error in API call ',error);
        throw new Error('Error in API call');
    }
}


const getToken=async()=>{
    try {
        const urlParams={
            grant_type:'client_credentials',
            client_id:CLIENT_ID,
            client_secret:CLIENT_SECRET
        }
        const config={
            method:'POST',
            url:`${KEYCLOAK_DOMAIN}/auth/realms/${REALM_NAME}/protocol/openid-connect/token`,
            headers:{
                'Content-Type':'application/x-www-form-urlencoded'
            },
            data:querystring.stringify(urlParams)
        }
        const tokenResponse= await processRequest(config);
        console.log('tokenResponse ',tokenResponse);
        return tokenResponse.access_token;
    } catch (error) {
        console.error('Error in getting Admin token ',error);
        throw new Error('Error in fetching Admin token');
    }

}

module.exports={processRequest,getToken}