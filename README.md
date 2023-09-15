# Google Wallet Smart Tap sample app

The Smart Tap sample app is a simple Android application that invokes the
[`get smart tap data`](https://developers.google.com/wallet/smart-tap/reference/apdu-commands/get-data)
flow with the Smart Tap 2.1 protocol. The app reads the
`smartTapRedemptionValue` property of a Google Wallet pass object stored on an
Android-powered device. This includes the cryptographic operations needed to
authenticate the terminal and decrypt the payload.

For more information on the different data flows, see
[Data flow](https://developers.google.com/wallet/smart-tap/guides/implementation/data-flow).

## Prerequisites

You will need two different Android-powered devices to test the sample app. The
devices are listed below for reference.

* **Terminal device:** On this device, you will install the sample app
* **User device:** On this device, you will add a sample pass to the Google
  Wallet app
  * Make sure the device supports NFC (see this
    [support article](https://support.google.com/wallet/answer/12200245?visit_id=638060357507089968-2256101247&rd=1)
    for additional troubleshooting tips)

You will also need the latest version of
[Android Studio](https://developer.android.com/studio) on your local
workstation.

## About the sample app

This application contains the needed configuration to retrieve the demo pass
added to the user device:

* Private key
* Key version
* Collector ID

## User device setup

On the user device, open the following link to add the demo loyalty pass to the
Google Wallet app:

[Demo pass **Add to Google Wallet** link](https://pay.google.com/gp/v/save/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnb29nbGUiLCJvcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJdLCJpc3MiOiJnb29nbGUtcGF5LWZvci1wYXNzZXMtZ3RlY2hAcGF5LXBhc3Nlcy1zbWFydC10YXAtc2FtcGxlLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiaWF0IjoxNTI5OTU2MDcwLCJ0eXAiOiJzYXZldG9hbmRyb2lkcGF5IiwicGF5bG9hZCI6eyJsb3lhbHR5T2JqZWN0cyI6W3siY2xhc3NJZCI6IjMyNjUzMjAxMTE2NDE5NTYxODMuMDYxOV9nb29nbGVEZW1vVGVzdCIsInN0YXRlIjoiYWN0aXZlIiwiaWQiOiIzMjY1MzIwMTExNjQxOTU2MTgzLjA2MTlfZ29vZ2xlRGVtb1Rlc3Qtb2JqMDEifV19fQ.MjUBdBtGyQwcE3xI-q6tVNBiApZppLMp0Op0XvB-c31Ri-JttJCzGXZvURNvKFDGXTNQQDqVBgQziuBMR_ZL0_lp7q8B5nwfSR32I0Kr220n3CezAsikaM5rKVf83UXT9fvqagnRn0QVVuS7fyLLc9nBDxRhRnkqEz2dQPgrNZ1u2AEJBPSoM6sLTeHssOWUMp7dgW6REJg7NUcczXJgLSOpAmD08G14q1qfS5T4Jb4knwPeIMnggNMjHcSBmz0z6W4DGD5Ld16nKOty4TvoDh4EevEJF7U7UQcOwIpozIXRVKs8rlqEXMObGsrk4hPM-I2p6H4DBrVcpyG8HD6Iug)

## Run the sample app

1. Clone this repository
2. Open Android Studio and import the repository folder
3. Connect your terminal device for debugging (for instructions on how to do so, 
   see the [Android Studio documentation](https://developer.android.com/studio/run/device))
5. Run the sample app in debugging mode on the terminal device
6. Gently tap the user device to the terminal device
   * The tap location may depend on the location of the NFC antenna on each
    device, so you may need to try tapping in several different locations

Once the devices connect via NFC, the terminal device will display the flow of
Smart Tap commands and responses, as well as the decrypted payload (`2018`).
This is the value stored in the pass object's `smartTapRedemptionValue`
property. The user device will show that the pass was successfully transmitted
to the terminal device.

**Note:** If you would like to inspect the flow further, set several breakpoints
at different locations in the sample terminal app and restart debugging.

### Support

Feel free to
[submit an issue](https://github.com/google-pay/smart-tap-sample-app/issues/new)
to this repository with any questions.

## Own data & information

On **Error 6999**: On device with wallet go to 'settings' - 'connection' - 'NFC..' - 'tap and pay...' 
now chose 'others' (not 'payment') - select 'Google Wallet'

Source: https://github.com/google-pay/smart-tap-sample-app

Demo pass: https://pay.google.com/gp/v/save/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnb29nbGUiLCJvcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJdLCJpc3MiOiJnb29nbGUtcGF5LWZvci1wYXNzZXMtZ3RlY2hAcGF5LXBhc3Nlcy1zbWFydC10YXAtc2FtcGxlLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiaWF0IjoxNTI5OTU2MDcwLCJ0eXAiOiJzYXZldG9hbmRyb2lkcGF5IiwicGF5bG9hZCI6eyJsb3lhbHR5T2JqZWN0cyI6W3siY2xhc3NJZCI6IjMyNjUzMjAxMTE2NDE5NTYxODMuMDYxOV9nb29nbGVEZW1vVGVzdCIsInN0YXRlIjoiYWN0aXZlIiwiaWQiOiIzMjY1MzIwMTExNjQxOTU2MTgzLjA2MTlfZ29vZ2xlRGVtb1Rlc3Qtb2JqMDEifV19fQ.MjUBdBtGyQwcE3xI-q6tVNBiApZppLMp0Op0XvB-c31Ri-JttJCzGXZvURNvKFDGXTNQQDqVBgQziuBMR_ZL0_lp7q8B5nwfSR32I0Kr220n3CezAsikaM5rKVf83UXT9fvqagnRn0QVVuS7fyLLc9nBDxRhRnkqEz2dQPgrNZ1u2AEJBPSoM6sLTeHssOWUMp7dgW6REJg7NUcczXJgLSOpAmD08G14q1qfS5T4Jb4knwPeIMnggNMjHcSBmz0z6W4DGD5Ld16nKOty4TvoDh4EevEJF7U7UQcOwIpozIXRVKs8rlqEXMObGsrk4hPM-I2p6H4DBrVcpyG8HD6Iug

Google Wallet rest-examples: https://github.com/google-wallet/rest-samples

Codelab: https://codelabs.developers.google.com/add-to-wallet-android#0

Codelab code: https://github.com/google-wallet/android-codelab/tree/main

Smart bonus overview: https://developers.google.com/wallet/smart-tap/introduction/overview?hl=de

Google Pay API sample app for Android: https://github.com/google-pay/android-quickstart

How to configure an Android device to read Google Wallet Smart Tap passes: https://contactless.wiki/article/how-to-read-smart-tap-on-android

Stackoverflow question: https://stackoverflow.com/questions/77100896/generate-and-read-nfc-smart-tap-generic-pass-in-google-wallet

Generate random NFC Passes: https://pub1.pskt.io/c/gn1v07

Passkit sample passes: https://passkit.com/samples/


```plaintext
Generate and Read NFC Smart Tap Generic Pass in Google Wallet

I'm trying to integrate and use Google Wallet (API and Android SDK) for generating a Generic Pass with Smart Tap enabled, read it using another mobile phone and decrypt the payload.

PRE:

Given that there is already a google provided sample: https://github.com/google-pay/smart-tap-sample-app
The given sample works on my mobile phone reading NFC demo pass from google (see README link of the github project)
Given that, at the url https://pub1.pskt.io/c/gn1v07 is is possible to generate random NFC Passes that have publicly available required info (CollectorID, Private Key, Public Key)
Given that with pskt passes (3) and sample app (1) i can read those passes
I can't read my custom passes, or, to be precise, I don't receive the correct payload.

My current passes are in "Demo Mode", because I want to be sure they work before ask for publishing. The google documentation is not clear wether or not this is a blocker or what to do in these case. I tried to upload the pskt (3) public key (with a different version) in my wallet console, but still doesn't work. The collector ID is the one I have in my google wallet console (converted to byte) and my issuerID has been added to redemptionIssuers. it seems that smartTapRedemptionValue is not written in the tag, but if I query wallet API it is there:

{
  "cardTitle": {
    "defaultValue": {
      "kind": "walletobjects#translatedString",
      "language": "it",
      "value": "$TITLE"
    },
    "kind": "walletobjects#localizedString"
  },
  "classId": "$ISSUER_ID.$CLASS_NAME",
  "genericType": "genericTypeUnspecified",
  "hasUsers": true,
  "header": {
    "defaultValue": {
      "kind": "walletobjects#translatedString",
      "language": "it",
      "value": "$HEADER"
    },
    "kind": "walletobjects#localizedString"
  },  
  "hexBackgroundColor": "#ffffff",
  "id": "$ISSUER_ID.newPassObject3",
  "smartTapRedemptionValue": "if_you_read_this_it's_great!",
  "state": "active",
  "subheader": {
    "defaultValue": {
      "kind": "walletobjects#translatedString",
      "language": "it",
      "value": "$SUBHEADER"
    },
    "kind": "walletobjects#localizedString"
  }
}
If anyone has any clue, thanks for the help!
13.09.2023 N Dorigatti

Own answer: I found what was the issue, and it wasn't an issue of the pass.

TL:DR -> Sample app is partial and full of missing pieces.

Digging in documentation and various reverse engineering, I found a 'Service Type' code usage, that was hardcoded in the app: 
https://github.com/google-pay/smart-tap-sample-app/blob/192d1760bd8f44e8142dda6611c2a1314b35595b/app/src/main/java/com/google/smarttapsample/GetDataCommand.java#L37

Here is set to Loyalty Cards (0x03). If you want to make it work with generic passes, you have to put Generic (0x12). 
In addition, there is an update to GetDataResponse method getDecryptedPayload: 
https://github.com/google-pay/smart-tap-sample-app/blob/192d1760bd8f44e8142dda6611c2a1314b35595b/app/src/main/java/com/google/smarttapsample/GetDataResponse.java#L258

You should add an "else if" for managing generic cards:

// Iterate over service NDEF records
for (NdefRecord serviceRecord : serviceNdefRecord.getRecords()) {
    // Check for `ly` type.   
    if (Arrays.equals(serviceRecord.getType(), new byte[]{(byte) 0x6c, (byte) 0x79})) {
        //.... processLoyaltyServiceRecord(serviceRecord);
    } else if (Arrays.equals(serviceRecord.getType(), new byte[]{(byte) 103, (byte) 114})) {
        processGenericServiceRecord(serviceRecord);
    }
}

    private void processGenericServiceRecord(NdefRecord serviceRecord) throws FormatException {
        //in case of general pass `gr` type
        // Get the generic record payload
        NdefMessage genericRecordPayload = new NdefMessage(serviceRecord.getPayload());
        for (NdefRecord generic : genericRecordPayload.getRecords()) {
            // Check for `n` ID = 6e
            if (Arrays.equals(generic.getId(), new byte[]{(byte) 0x6e})) {
                // Get the Smart Tap redemption value
                decryptedSmartTapRedemptionValue = new String(Arrays.copyOfRange(generic.getPayload(), 1, generic.getPayload().length));
            }
        }
    }
And now reading the pass works correctly!

Q: Did you change the LONG_TERM_PRIVATE_KEY field to your own as well or just the Collector ID?
A: Hi, I changed both, and also the key version that was hardcoded somewhere. I found the issue, i'll post a comment as soon as I have a few minutes for that! thanks for the help

Hi Michael, in order to read the pass from the link, you have to keep the service type to loyalty cards 
(pskt cards are loyalty cards). Other than that, if you click on the three dots of the pass (on your phone), 
you will see collector id and private key. Use the PrivKey in Utils class (replace the one there) and convert 
your decimal value of the collector ID to a byte array, then the code should work!

Changes in:
MainActivity.java: lines 347ff
GetDataResponse getDataResponse = new GetDataResponse(...
change CollectorId

NegotiateCryptoCommand.java 
lines 50..
change CollectorId and private static final String LONG_TERM_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n"

lines 90...
NegotiateCryptoCommand(byte[] mobileDeviceNonce) throws Exception {
change createCollectorIdRecord(); /

lines 161...
private void createCollectorIdRecord() throws IOException {
change CollectorId 

line 187...
private NdefRecord createSignatureRecord(byte[] mobileDeviceNonce)
change byte[] signedData = generateSignature(mobileDeviceNonce); 
to byte[] signedData = generateSignaturePasskit(mobileDeviceNonce);

line 218...
private byte[] generateSignature(byte[] mobileDeviceNonce)
change collectorId
signature.update(COLLECTOR_ID);



old value of collector id: 
// Collector ID is hardcoded to `20180608` for this sample app
// static final byte[] COLLECTOR_ID = new byte[]{(byte) 0x01, (byte) 0x33, (byte) 0xEE, (byte) 0x80};
// see https://www.scadacore.com/tools/programming-calculators/online-hex-converter/
// using 0133ee80 gives:
// INT32 - Big Endian (ABCD) 20180608

Collector id 13380028

Private Key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEID0VR/I814rQUqWIYPEhno+3kexN/jN2n1ub+mJ6ZWyhoAoGCCqGSM49
AwEHoUQDQgAEwKMBv29ByaSLiGF0FctuyB+Hs2oZ1kDIYhTVllPexNGudAlm8IWO
H0e+Exc97/zBdawu7Yl+XytQONszGzAK7w==
-----END EC PRIVATE KEY-----

Public key
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwKMBv29ByaSLiGF0FctuyB+Hs2oZ
1kDIYhTVllPexNGudAlm8IWOH0e+Exc97/zBdawu7Yl+XytQONszGzAK7w==
-----END PUBLIC KEY-----

Payload
2A8ZQaXyW86CBuZIH7tgVM
 ```


