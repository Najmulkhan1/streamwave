import { prisma } from "@/lib/db";
import bcrypt from "bcryptjs";
import { NextResponse } from "next/server"



export async function POST(req: Request) {
    try {
        const body = await req.json()
        const { email, password} = body

        if (!email || !password) {
            return NextResponse.json(
                {error: "Email and password are required"},
                {status: 400}
            )
        }

        const existingUser = await prisma.user.findUnique({
            where: {email}
        })

        if(existingUser) {
            return NextResponse.json(
                {error: "A user with this email already exists"},
                {status: 409}
            )
        }

        const passwordHash = await bcrypt.hash(password, 12)

        const newUser = await prisma.user.create({
            data: {
                email,
                passwordHash
            }
        })

        return NextResponse.json(
            {message: "User register successfully", userId: newUser.id},
            {status: 201}
        )
    } catch(error){
        console.error("Register Error", error)
        return NextResponse.json(
            {error: "Internal server error"},
            {status: 500}
        )
    }
}