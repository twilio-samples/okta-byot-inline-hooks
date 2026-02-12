exports.handler = async function(context, event, callback) {
  try {
    console.log(event.request.headers);

    if (context.auth_secret !== event.request.headers.auth_secret) {
      throw new Error("Authentication failed");
    }

    let client = context.getTwilioClient();

    // https://developer.okta.com/docs/reference/telephony-hook/#data-messageprofile
    let to = event.data.messageProfile.phoneNumber;
    let customCode = event.data.messageProfile.otpCode;
    let channel =
      event.data.messageProfile.deliveryChannel.toLowerCase() === "sms" ?
      "sms" :
      "call";

    let verification = await client.verify.v2
      .services(context.VERIFY_SID)
      .verifications.create({
        to,
        channel,
        customCode
      });

    console.log(verification);
    console.log(verification.sendCodeAttempts);

    let response = {
      commands: [{
        type: "com.okta.telephony.action",
        value: [{
          status: "SUCCESSFUL",
          provider: "Twilio Verify",
          transactionId: verification.sid,
          transactionMetadata: verification.sendCodeAttempts.at(-1).attempt_sid,
        }],
      }],
    };

    return callback(null, response);
  } catch (error) {
    console.error("Error: " + error);
    let errorResponse = {
      error: {
        errorSummary: error.message,
        errorCauses: [{
          errorSummary: error.status || error.message,
          reason: error.moreInfo || error.message,
        }],
      },
    };
    return callback(null, errorResponse);
  }
};
