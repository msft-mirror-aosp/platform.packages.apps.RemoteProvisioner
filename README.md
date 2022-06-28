# RemoteProvisioner Platform Application
RemoteProvisioner is the application responsible for driving the provisioning process for Remote Key
Provisioning (RKP) between the device and server.

## Primary Features

### Periodic Provisioning
The application registers a periodic job using
[WorkManager](https://developer.android.com/jetpack/androidx/releases/work). This job is scheduled
to run once every ~24 hours in order to check the status of the attestation key pool and determine
if further provisining is needed. An active network connection is set as a prerequisite for the job
to be executed.

### On Demand Provisioning
RemoteProvisioner publishes an implementation of the [IGenerateRkpKeyService][1]. The Keystore
frameworks code registers with this interface and notifies the application whenever the following
conditions are met:
1. An attested key is generated by an application, meaning an RKP key **may** have been consumed.
2. Key generation is attempted, but fails due to no available attestation keys.

In the event of `(1)`, the application will just check the key pool state in Keystore to determine
if provisioning should be executed immediately, rather than waiting for the periodic provisioning
check. In the event of `(2)`, the binder call will block until the RemoteProvisioner can complete
a provisioning step, allowing the original key generation request from the frameworks to
seamlessly attempt generation again using one of the newly provisioned keys.

### Widevine Provisioning
The RemoteProvisioner will also check the status of Widevine on device during boot. There are two
relevant details to check before the application will take any further action related to Widevine:
1. Check if the Widevine instance on device is based on the Provisioning 4.0 model.
2. If `(1)` then check if the device is unprovisioned.

If `(1)` and `(2)` are both true, the application will create a separate Widevine job which will
trigger once network is made available in order to attempt to provision the stage 1 Widevine
certificate before it's needed by other streaming services on device.

This exists as a convenience step, and should only ever run one time for a given device unless it
is factory reset.

## Device to Server Communication

### Server-controlled Device Configuration
The device code is written such that a backing server implementation can set some variables on the
application side, stored in
[SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences).
These preferences are managed by
[SettingsManager](/src/com/android/remoteprovisioner/SettingsManager.java). Server configurable
variables include:
* Key Expiration: How many hours into the future should the application check when considering if a
  key will be expiring soon.
* Extra Keys: How many additional unassigned attestation keys should the device ideally keep ready
  in order to service attestation requests from new applications.
* URL: A new URL to use, intended to be used to migrate a device to newer versions of the backing
  web API if necessary.

All or none of these variables may be present when the device receives them during a fetchEek
request. Notably, the device also generates and sets an ID that it sends to the server during this
fetchEek request, along with its build fingerprint. This allows the backend to configure different
options for different device models if necessary, while supporting controlled rollout of new
changes.

[1]: https://cs.android.com/android/platform/superproject/+/master:frameworks/base/keystore/java/android/security/IGenerateRkpKeyService.aidl