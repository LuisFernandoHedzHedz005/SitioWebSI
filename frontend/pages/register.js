// pages/register.js
import { useState } from 'react';
import Router from 'next/router';
import Link from 'next/link';

export default function Register() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('user'); // Por defecto 'user'
    const [err, setErr] = useState('');

    async function submit(e) {
        e.preventDefault();
        //const res = await fetch('http://3.22.196.59:5000/api/register', {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, role })
        });
        const data = await res.json();
        if (res.ok) {
            Router.push('/login');
        } else {
            setErr(data.error || 'Error en el registro');
        }
    }

    return (
        <main className="form-container">
            <h2>Crear Cuenta</h2>
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
                {/* Ocultamos la selección de rol para un gimnasio, ya que normalmente lo asigna un admin.
                Si quieres mantenerlo, descomenta este bloque.
                <div className="form-group">
                    <label>Rol</label>
                    <select className="form-select" value={role} onChange={e => setRole(e.target.value)}>
                        <option value="user">Usuario</option>
                        <option value="admin">Administrador</option>
                    </select>
                </div>
                */}
                <button type="submit" className="btn-primary">Registrar</button>
            </form>
            {err && <p className="error-message">{err}</p>}
            <p className="form-link">
                ¿Ya tienes una cuenta? <Link href="/login">Inicia Sesión</Link>
            </p>
        </main>
    );
}
