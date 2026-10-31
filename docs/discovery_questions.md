# Discovery questions (fictional prospect)
1. How are you currently investigating IAM activity across your AWS accounts?
2. When something suspicious happens, what's the most time-consuming step?
3. What does delayed investigation mean for your team or business?
4. How do you currently measure incident investigation time and coverage?
5. What would you need to see in a short technical validation to consider this useful?

## Check-back
"So, if I've understood correctly, the challenge isn't that CloudTrail doesn't record activity; it's that your team needs a quicker way to bring related events together. Is that right?"

## Demo flow (~15 minutes)
- 0-2: discovery / confirm the pain
- 2-4: architecture and data provenance (clearly label synthetic data)
- 4-7: show failed-sign-in cluster
- 7-10: show successful login without MFA and later IAM policy attachment
- 10-12: investigate timeline and limitations
- 12-15: value hypothesis, validation metrics, next steps

Do not claim a confirmed compromise or measured ROI. This is a fictional scenario and educational prototype, not Splunk Enterprise Security correlation content.
