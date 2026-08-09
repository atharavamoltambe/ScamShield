import React from "react";

const EXAMPLES = [
  {
    id: "rto",
    label: "RTO / e-Challan",
    text: "TRAFFIC POLICE NOTICE. Your vehicle has an unpaid challan. Pay within 24 hours to avoid legal action. Download RTO_Challan.apk\nhttps://parivahaan.com/pay"
  },
  {
    id: "kyc",
    label: "Banking / KYC",
    text: "URGENT: Your bank account is blocked due to expired KYC details. Verify your credentials immediately to restore access: http://sbi-verify.xyz/kyc"
  },
  {
    id: "delivery",
    label: "Delivery / Customs",
    text: "Your DHL parcel is held at the warehouse due to an incorrect delivery address. Pay ₹50 customs clearance fee here: http://cutt.ly/delivery-tracker"
  },
  {
    id: "job",
    label: "Job / WFH Offer",
    text: "Congratulations! You have been selected for a flexible online job earning ₹5,000 daily. Pay ₹499 processing fee to secure your spot now."
  }
];

export default function ExampleMessages({ onSelectExample }) {
  return (
    <div className="examples-container">
      <h3 className="examples-title">Try a sample message</h3>
      <p className="examples-subtitle">
        Not sure what type of scam it is? Just paste the message — Scam Shield will identify the pattern automatically.
      </p>
      <div className="example-chips">
        {EXAMPLES.map((example) => (
          <button
            key={example.id}
            type="button"
            className="example-chip"
            onClick={() => onSelectExample(example.text)}
          >
            {example.label}
          </button>
        ))}
      </div>
    </div>
  );
}
