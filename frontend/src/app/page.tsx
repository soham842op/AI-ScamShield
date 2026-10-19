import { AnalyzeForm } from "@/components/AnalyzeForm";

export default function Home() {
  return (
    <main className="mx-auto max-w-2xl px-4 py-12">
      <h1 className="text-3xl font-semibold">AI ScamShield</h1>
      <p className="mt-3 mb-8">
        Paste a suspicious message or link to see the warning signs we found. A
        result is a risk assessment, not a guarantee.
      </p>
      <AnalyzeForm />
    </main>
  );
}
