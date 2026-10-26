package grade

import "github.com/ditto-assistant/dittobench-datagen/protocol"

// AuditBankV14 is the public grader-robustness bank for the v14 policy. V14
// keeps every v13 typed-claim rule and adds two reply-reading changes: a
// sentence that is exactly a reviewed claim value is not a correction cue
// (#2769), and U+2010 and U+2011 read as the ASCII hyphen (#2734). The bank
// therefore carries the v13 strategies, cases, negatives, and limits
// unchanged, plus reviewed positives for each change and negatives proving
// neither can credit a distractor, leak a forbidden value, or excuse a real
// correction.
func AuditBankV14() AuditBank {
	bank := AuditBankV13()
	bank.Version = "v14-1"
	bank.FloorBenchVersion = protocol.BenchVersionV14
	bank.Negatives = append(append([]AuditNegative(nil), auditNegativesV13...), auditNegativesV14...)
	bank.Positives = append(append([]AuditPositive(nil), auditPositivesV13...), auditPositivesV14...)
	return bank
}

var handleVK = protocol.MemoryCase{AnswerKind: protocol.AnswerValue, ExpectedAnswer: "VK-48HJXP6A63", DistractorAnswers: []string{"VK-48HJXP6A36"}}

var lessonSafeSorry = protocol.MemoryCase{
	QuestionType:   "world-story-lesson-claims",
	Question:       "What did I take away from the whole thing?",
	AnswerKind:     protocol.AnswerList,
	ExpectedAnswer: "safe; sorry",
	AnswerItems:    []string{"safe", "sorry"},
	Claims: []protocol.Claim{
		{Kind: protocol.ClaimKindConcept, Expected: "safe", Weight: 1,
			Accept: []string{"caution", "careful", "cautious", "play it safe", "better safe than sorry"}},
		{Kind: protocol.ClaimKindConcept, Expected: "sorry", Weight: 1,
			Accept: []string{"regret", "regretting it", "pay for it later", "wishing you had", "better safe than sorry"}},
	},
}

var auditPositivesV14 = []AuditPositive{
	{Name: "v14-claim-value-cue-in-slot", Case: lessonSafeSorry, Response: protocol.RunResponse{Answer: "safe; sorry", FinalText: "safe; sorry"}},
	{Name: "v14-claim-value-cue-as-sentence", Case: lessonSafeSorry, Response: protocol.RunResponse{FinalText: "Safe. Sorry."}},
	{Name: "non-breaking-hyphen-identifier", Case: handleVK, Response: protocol.RunResponse{FinalText: "The Signal handle you have is **VK‑48HJXP6A63**. Answer: VK‑48HJXP6A63"}},
	{Name: "hyphen-identifier-in-slot", Case: handleVK, Response: protocol.RunResponse{Answer: "VK‐48HJXP6A63", FinalText: "Your handle is VK‐48HJXP6A63."}},
}

var auditNegativesV14 = []AuditNegative{
	{Name: "v14-unprotected-correction-still-retracts", Case: lessonSafeSorry, Response: protocol.RunResponse{FinalText: "Safe. Actually, reckless."}},
	{Name: "non-breaking-hyphen-distractor", Case: handleVK, Response: protocol.RunResponse{FinalText: "Your handle is VK‑48HJXP6A36."}},
	{Name: "non-breaking-hyphen-forbidden-leak", Case: protocol.MemoryCase{AnswerKind: protocol.AnswerChitchat, ForbiddenAnswer: "GAVOTU-8841"}, Response: protocol.RunResponse{FinalText: "GAVOTU‑8841"}},
}
