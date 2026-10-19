import type { components } from "./schema";

type S = components["schemas"];

export type AnalysisResponse = S["AnalysisResponse"];
export type MessageAnalysisRequest = S["MessageAnalysisRequest"];
export type UrlAnalysisRequest = S["UrlAnalysisRequest"];
export type FeedbackRequest = S["FeedbackRequest"];
export type FeedbackResponse = S["FeedbackResponse"];
export type ErrorEnvelope = S["ErrorEnvelope"];
export type ErrorDetail = S["ErrorDetail"];

export type Channel = NonNullable<MessageAnalysisRequest["channel"]>;
export type Verdict = NonNullable<FeedbackRequest["verdict"]>;
