import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI ScamShield",
  description: "Check a suspicious message or URL for scam warning signs.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
