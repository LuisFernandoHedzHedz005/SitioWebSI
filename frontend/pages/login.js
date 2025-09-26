// pages/login.js
import { useState } from 'react';
import Router from 'next/router';
import Link from 'next/link';

export default function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [err, setErr] = useState('');

    async function submit(e) {
        e.preventDefault();
        //const res = await fetch('http://3.22.196.59:5000/api/login', {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (res.ok) {
            localStorage.setItem('token', data.token);
            Router.push('/dashboard');
        } else {
            setErr(data.error || 'Error al iniciar sesión');
        }
    }

    return (
        <main className="form-container">
            <h2>Iniciar Sesión</h2>
            <form onSubmit={submit}>
                <div className="form-group">
                    <label htmlFor="email">Email</label>
                    <input 
                        id="email"
                        className="form-input" 
                        value={email} 
                        onChange={e => setEmail(e.target.value)} 
                        required 
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="password">Contraseña</label>
                    <input 
                        id="password"
                        type="password" 
                        className="form-input" 
                        value={password} 
                        onChange={e => setPassword(e.target.value)} 
                        required 
                    />
                </div>
                <button type="submit" className="btn-primary">Entrar</button>
            </form>
            {err && <p className="error-message">{err}</p>}
            <p className="form-link">
                ¿No tienes una cuenta? <Link href="/register">Regístrate</Link>
            </p>
        </main>
    );
}
