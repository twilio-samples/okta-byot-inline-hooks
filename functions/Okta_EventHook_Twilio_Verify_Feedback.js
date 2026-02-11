const okta = require("@okta/okta-sdk-nodejs");

exports.handler = async function (context, event, callback) {
  // Track execution time to monitor for 10-second Twilio Function timeout
  const startTime = Date.now();

  try {
    //one off check when enable Okta event inline hook, required by Okta
    const verificationValue =
      event.request?.headers?.["x-okta-verification-challenge"];
    if (verificationValue) {
      console.log("Verifying");
      return callback(
        null,
        JSON.stringify({ verification: verificationValue }),
      );
    }

    if (context.auth_secret !== event.request?.headers?.auth_secret) {
      throw new Error("Authentication failed");
    }

    console.log("event data: ", JSON.stringify(event.data));

    const events = event.data?.events || [];
    if (events.length === 0) {
      return callback(null, []);
    }

    console.log(
      `Starting processing of ${events.length} event(s) at ${new Date().toISOString()}`,
    );

    // Initialize clients once for all events (instead of per-event)
    // This improves performance by reusing connections across all event processing
    const OktaClient = new okta.Client({
      orgUrl: context.okta_org_baseurl,
      token: context.okta_auth_token,
    });
    const twilioClient = context.getTwilioClient();

    // Process all events in parallel to avoid timeout with large batches
    // Promise.allSettled ensures all events are processed even if some fail
    const results = await Promise.allSettled(
      events.map(async (mfa_event) => {
        try {
          if (context.LOG_FINER_DETAILS === "true") {
            console.log("mfa_event details:", {
              mfa_event: JSON.stringify(mfa_event),
              client: JSON.stringify(mfa_event?.client),
              actor: JSON.stringify(mfa_event?.actor),
              outcome: JSON.stringify(mfa_event?.outcome),
              target: JSON.stringify(mfa_event?.target),
              transaction: JSON.stringify(mfa_event?.transaction),
              debugContext: JSON.stringify(mfa_event?.debugContext),
              authenticationContext: JSON.stringify(
                mfa_event?.authenticationContext,
              ),
              securityContext: JSON.stringify(mfa_event?.securityContext),
            });
          }

          let channel = null;
          //check payload of "user.authentication.auth_via_mfa" and "user.mfa.factor.activate" for SMS OTP and CALL OTP
          if (
            mfa_event &&
            mfa_event.outcome?.result === "SUCCESS" &&
            (mfa_event.debugContext?.debugData?.factor === "SMS_FACTOR" ||
              mfa_event.outcome?.reason?.includes("SMS_FACTOR"))
          ) {
            channel = "sms";
          } //SMS OTP is used
          else if (
            mfa_event &&
            mfa_event.outcome?.result === "SUCCESS" &&
            (mfa_event.debugContext?.debugData?.factor === "CALL_FACTOR" ||
              mfa_event.outcome?.reason?.includes("CALL_FACTOR"))
          ) {
            channel = "call";
          } //call OTP is used

          console.log(
            "Pre factor Channel for user: " + mfa_event.actor?.id + " is: ",
            channel,
          );
          if (channel !== null) {
            const userid = mfa_event.actor?.id; //grab user id
            let phone_number = null;
            //get the list of enrolled factors (such as sms, call etc)
            const factors = await OktaClient.userFactorApi.listFactors({
              userId: userid,
            });

            for await (const factor of factors) {
              //in Okta, user can enroll different phone numbers for SMS factor and call factor respectively, thus have to grab the phone number based on the actual factor used in MFA
              if (factor.factorType === channel) {
                phone_number = factor.profile.phoneNumber;
                console.log(
                  "Determined channel for user: " + userid + " is: ",
                  channel,
                );
                console.log(
                  "MFA phone number for user: " + userid + " is: ",
                  phone_number,
                );
                break; // Performance: stop iterating once we find the matching factor
              }
            }
            if (phone_number === null) {
              console.log(
                "can't retrieve phone number for user: " +
                  userid +
                  ", possible not SMS OTP or Voice OTP MFA factor",
              );
              return {
                userId: userid,
                status: "failed",
                message:
                  "can't retrieve phone number, possible not SMS OTP or Voice OTP MFA factor",
              };
            }

            //call Verify feedback API using phone number
            let verification = await twilioClient.verify.v2
              .services(context.VERIFY_SID)
              .verifications(phone_number)
              .update({ status: "approved" });

            console.log(
              "Verification response for user " + userid + ": ",
              JSON.stringify(verification),
            );
            return {
              userId: userid,
              status: "success",
              verification: verification,
            };
          } else {
            console.log(
              "not SMS OTP or Voice OTP MFA factor available for user: " +
                mfa_event.actor?.id,
            );
            return {
              userId: mfa_event.actor?.id,
              status: "skipped",
              message: "not SMS OTP or Voice OTP MFA factor",
            };
          }
        } catch (eventError) {
          console.error(
            "Error processing event for user " + mfa_event.actor?.id + ": ",
            eventError,
          );
          return {
            userId: mfa_event.actor?.id,
            status: "error",
            error: eventError.message,
          };
        }
      }),
    );

    // Extract results from Promise.allSettled
    // Convert settled promises to consistent result objects (fulfilled values or error objects)
    const finalResults = results.map((r, index) =>
      r.status === "fulfilled"
        ? r.value
        : {
            userId: events[index]?.actor?.id,
            status: "error",
            error: r.reason?.message || "Unknown error",
          },
    );

    // Log execution time for monitoring and debugging
    const executionTime = Date.now() - startTime;
    console.log(
      `Processing complete. Execution time: ${executionTime}ms for ${events.length} event(s)`,
    );

    // Warn if approaching timeout (80% of 10-second limit)
    // This helps identify batches that might timeout in production
    if (executionTime > 8000) {
      console.warn(
        `WARNING: Execution time ${executionTime}ms is close to 10s timeout limit`,
      );
    }

    // Return just the results array to maintain backward compatibility
    return callback(null, finalResults);
  } catch (error) {
    const executionTime = Date.now() - startTime;
    console.error(`Error after ${executionTime}ms:`, error);
    // Return error object to match original behavior
    return callback(null, error);
  }
};
