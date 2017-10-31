const KerberosAuthProvider = require('./lib/kerberosAuthProvider.js').KerberosAuthProvider;

module.exports['processes'] = {
  MongoAuthProcess: require('./lib/auth_processes/mongodb').MongoAuthProcess
};

module.exports = function(options) {
  return function(connection) {
    console.log('new KerberosAuthProvider ');
    return new KerberosAuthProvider(connection, options);
  };
};
