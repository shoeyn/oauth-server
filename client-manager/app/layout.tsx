import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "OAuth 2.1 Admin Manager",
  description: "Administrative dashboard for managing OAuth 2.1 clients and platform users",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-slate-950 text-slate-100 min-h-screen flex flex-col`}
      >
        <header className="bg-slate-900 border-b border-slate-800">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16 items-center">
              <div className="flex">
                <div className="shrink-0 flex items-center gap-2">
                  <span className="font-bold text-xl tracking-tight text-white">
                    OAuth 2.1 Admin
                  </span>
                </div>
                <div className="ml-6 flex space-x-4">
                  <Link
                    href="/"
                    className="text-slate-300 hover:bg-slate-700 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                  >
                    Clients
                  </Link>
                  <Link
                    href="/users"
                    className="text-slate-300 hover:bg-slate-700 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                  >
                    Users
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </header>
        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">{children}</main>
      </body>
    </html>
  );
}
