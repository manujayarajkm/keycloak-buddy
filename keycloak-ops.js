const {getToken,processRequest}= require("./util");
const {KEYCLOAK_DOMAIN,REALM_NAME}= process.env;

const getUsers=async()=>{
    try {
        const token= await getToken();
        let userData = [];
        console.log('token ',token);
        if(token){
            const url=`${KEYCLOAK_DOMAIN}/admin/realms/${REALM_NAME}/users`
            const config={
                url,
                method:'GET',
                headers:{
                    Authorization:`Bearer ${token.access_token}`
                }
            }
            userData=await processRequest(config);
            return userData
        }
        return userData;
    } catch (error) {
        console.error('Error ',error)
        throw new Error('Error in getting users');
    }
}

module.exports = {getUsers}