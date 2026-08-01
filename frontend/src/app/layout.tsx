import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })

export const metadata: Metadata = {
  title: 'AEGIS SOC — AI-Integrated Cyber Defense',
  description: 'AI-Integrated Security Operations Center & Incident Command',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} font-sans bg-[#04050d] text-[#f0f0f5] antialiased selection:bg-[#00f0ff] selection:text-black min-h-screen`}>
        {children}
      </body>
    </html>
  )
}
