const Kerberos = require('./kerberos.js').Kerberos;

class KerberosAuthProvider {
  constructor(connection, options) {
    this.connection = connection;
    this.context = undefined;
  }

  handshake(data, callback) {
    if (this.sspiClientResponsePending) {
      const boundDispatchEvent = this.connection.dispatchEvent.bind(this.connection);
      return setImmediate(boundDispatchEvent, 'message');
    }
    if (data) {
      this.sspiClientResponsePending = true;
      this.kerberos.authGSSClientStep(this.context,
        data.toString('base64', 0, data.length), (err, result) => {
          if (err) {
            callback(new Error(err.toString()));
          }

          //verify if kerberos auth was successful, ie, GSS_C_COMPLETE flag returned
          if (!((null != result) && ('number' === typeof (result)) && (1 === result /* GSS_C_COMPLETE */))) {
            callback(new Error('Expected GSS_C_COMPLETE flag not received, kerberos authentication failed'));
          }

          this.sspiClientResponsePending = false;
          this.connection.sspiBuffer = undefined;

          // clean the security context after handshake
          this.kerberos.authGSSClientClean(this.context, () => callback(null));
        });
    }
    else {
      this.kerberos = new Kerberos();
      const spn = 'MSSQLSvc/' + this.connection.config.server;
      this.sspiClientResponsePending = true;
      this.kerberos.authGSSClientInitDefault(spn, Kerberos.GSS_C_MUTUAL_FLAG | Kerberos.GSS_C_INTEG_FLAG, (err, context) => {
        if (err) {
          return callback(new Error(err.toString()));
        }

        this.kerberos.authGSSClientStep(context, '', (err, result) => {
          if (err) {
            return callback(new Error(err.toString()));
          }
          this.context = context;
          //verify GSS_S_CONTINUE_NEEDED is returned after init_sec_context()
          if (!((null != result) && ('number' === typeof (result)) && (0 === result /* GSS_S_CONTINUE_NEEDED */))) {
            return callback(new Error('Expected GSS_S_CONTINUE_NEEDED flag not received, kerberos authentication failed'));
          }

          this.sspiClientResponsePending = false;
          callback(null, Buffer.from(this.context.response, 'base64'));
        });
      });
    }
  }
}

module.exports.KerberosAuthProvider = KerberosAuthProvider;
