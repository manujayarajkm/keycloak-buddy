const {getUsers}= require('./keycloak-ops');


const execute= async(option)=>{
    switch (option) {
        case "get-user-list":
            return await getUsers();
    
        default:
            throw new Error("Unsupported Option");
    }
}