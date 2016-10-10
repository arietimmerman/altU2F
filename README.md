
# altU2F

altU2F is a software implementation of the FIDO U2F authenticator.

This script allows you to use U2F technology on clients that do not support U2F. By using this script, one can authenticate to an U2F server with browser that do not support FIDO U2F, such as Firefox and Internet Explorer.

Note: This script is work in progress.

## What is FIDO U2F?

> "The FIDO U2F protocol enables relying parties to offer a strong cryptographic 2nd factor option for end user security. The relying party's dependence on passwords is reduced. The password can even be simplified to a 4 digit PIN. End users carry a single U2F device which works with any relying party supporting the protocol. The user gets the convenience of a single 'keychain' device and convenient security."
[fidoalliance.org](https://fidoalliance.org "")

# Example usage

Include both the [buffer](https://github.com/feross/buffer) module, the [jsrsasign](https://kjur.github.io/jsrsasign/), and the `altu2f.js` script on a page. Then, call `new altU2F()`.

~~~.html
<script type="text/javascript" src="lib/buffer.js"></script>
<script type="text/javascript" src="lib/jsrsasign-latest-all-min.js"></script>
<script type="text/javascript" src="altu2f.js"></script>

<script type="text/javascript">

new altU2F(
  {
    onStartSign : function(caller) {

      //wait for button press
      caller.userPresenceConfirmed();

    },
    onStartRegister : function(caller) {

      //wait for button press
      caller.userPresenceConfirmed();

		},
  }
);

</script>
~~~

# TODO

* Create an example application
* Clean up the code
* Documentation
