const util= require('./util');
const {getUsers}= require('./keycloak-ops');

util.getToken();
getUsers();