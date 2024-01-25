# SWArevealer

This is an implementation of the attack described in https://pushsecurity.com/blog/okta-swa/, all credit for discovery goes to them. 

I was specifically interested in the threat of "An attacker who has user credentials on an account which has password visibility disabled can get access to passwords". 

## Build

One the repository is cloned, it can be built with:

```
go build
```

## Usage

In order to run, this code needs the base url of your tenant (https://<something>.okta.com), as well as the username and password for an account. It will enumerate all SWA's assigned to that account and extract the password via the method in the referenced blog post

### Limitations

- This currently does not support MFA, but it would be trivial to add by modifying the `getSidForClient` method. I might get around to this at some point, but if you get there first, feel free to send over a PR ;).

- There's a parsing bug with the state token where sometimes a state token is given that has characters which are invalid to put in a cookie. This throws a general error and the causes the tool to stop. My workaround for this is to just run the tool again.
