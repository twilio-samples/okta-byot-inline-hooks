const okta = require('@okta/okta-sdk-nodejs');


exports.handler = async function(context, event, callback) {
  try {
    if (context.auth_secret !== event.request.headers.auth_secret) {
      throw new Error("Authentication failed");
    }

    // One-off verification check required by Okta when enabling event inline hooks
    // https://developer.okta.com/docs/concepts/event-hooks/#one-time-verification-request
    const verificationValue = event.request?.headers ? event.request.headers['x-okta-verification-challenge'] : null;
    if (verificationValue) {
      console.log("Verifying");
      return callback(null, { verification: verificationValue });
    }

    const oktaBaseUrl = context.okta_org_baseurl;
    const api_token = context.okta_auth_token;

    // Get all events from the array - Okta can bundle multiple events
    const mfa_events = event.data?.events || [];

    if (!Array.isArray(mfa_events) || mfa_events.length === 0) {
      console.log("No events to process");
      return callback(null, "No events to process");
    }

    console.log(`Processing ${mfa_events.length} event(s)`);

    const OktaClient = new okta.Client({ orgUrl: oktaBaseUrl, token: api_token });
    const client = context.getTwilioClient();

    const results = await Promise.all(mfa_events.map(async (mfa_event, index) => {
      console.log(`Processing event ${index + 1}/${mfa_events.length}`);
      let channel = null;

      // Checks payload for SMS OTP or CALL OTP factor types
      if (mfa_event && mfa_event.outcome?.result === 'SUCCESS' &&
          (mfa_event.debugContext?.debugData?.factor === 'SMS_FACTOR' ||
          mfa_event.outcome?.reason?.includes("SMS_FACTOR"))) {
        channel = "sms";
      }
      else if (mfa_event && mfa_event.outcome?.result === 'SUCCESS' &&
              (mfa_event.debugContext?.debugData?.factor === 'CALL_FACTOR' ||
                mfa_event.outcome?.reason?.includes("CALL_FACTOR"))) {
        channel = "call";
      }

      if (channel !== null) {
        const userid = mfa_event.actor?.id;
        let phone_number = null;

        const factors = await OktaClient.userFactorApi.listFactors({ userId: userid });

        for await (const factor of factors) {
          if (factor.factorType === channel) {
            phone_number = factor.profile.phoneNumber;
            console.log(`Event ${index + 1} - MFA factor is:`, channel);
            console.log(`Event ${index + 1} - MFA phone number is:`, phone_number);
            break; // Found the matching factor
          }
        }

        if (phone_number === null) {
          console.log(`Event ${index + 1} - Can't retrieve phone number, possible not SMS OTP or Voice OTP MFA factor`);
          return {
            eventIndex: index + 1,
            status: 'skipped',
            reason: "Can't retrieve phone number"
          };
        }

        try {
          let verification = await client.verify.v2.services(context.VERIFY_SID)
            .verifications(phone_number).update({status: 'approved'});

          console.log(`Event ${index + 1} - Verification '${verification.sid}' updated`);
          return {
            eventIndex: index + 1,
            status: 'success',
            phone_number: phone_number,
            verification_sid: verification.sid
          };
        } catch (verifyError) {
          if (verifyError.code === 20404) {
            console.log(`Event ${index + 1} - No pending verification found for ${phone_number}`);
            return {
              eventIndex: index + 1,
              status: 'skipped',
              reason: 'No pending verification found. The Verification has already processed or is no longer active.'
            };
          }
          console.error(`Event ${index + 1} - Error updating verification:`, verifyError);
          return {
            eventIndex: index + 1,
            status: 'error',
            error: verifyError.message
          };
        }
      }
      else {
        console.log(`Event ${index + 1} - Not SMS OTP or Voice OTP MFA factor`);
        return {
          eventIndex: index + 1,
          status: 'skipped',
          reason: 'Not SMS/Voice OTP factor'
        };
      }
    }));

    // Return summary of processed events
    const summary = {
      totalEvents: mfa_events.length,
      results: results
    };
    console.log("Processing complete:", summary);
    return callback(null, summary);
  }
  catch (error) {
    console.error(error);
    return callback(null, { error: error.message });
  }
};