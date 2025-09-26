// pages/dashboard.js
import { useEffect, useState } from 'react';
import Router from 'next/router';

export default function Dashboard() {
    const [user, setUser] = useState(null);

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            Router.push('/login');
            return;
        }

        //fetch('http://3.22.196.59:5000/api/me',
        fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/me`, {
            headers: { Authorization: `Bearer ${token}` }
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                Router.push('/login');
            } else {
                setUser(data);
            }
        });
    }, []);

    if (!user) {
        return <p>Cargando...</p>;
    }

    return (
        <main className="dashboard-container">
            <div className="dashboard-header">
                <h2>Bienvenido de nuevo, {user.email.split('@')[0]}!</h2>
                <p>Este es tu panel de control personal.</p>
            </div>
            
            <div className="dashboard-info">
                <h3>Tu Información</h3>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Rol:</strong> {user.role === 'admin' ? 'Administrador' : 'Miembro'}</p>
            </div>
            
            <button 
                onClick={() => {
                    localStorage.removeItem('token');
                    Router.push('/');
                }} 
                className="btn-primary btn-logout"
            >
                Salir
            </button>
        </main>
    );
}
