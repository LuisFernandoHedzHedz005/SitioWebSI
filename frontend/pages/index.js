// pages/index.js
import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function Home() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  return (
    <div className="home-container">
      {/* Hero Section */}
      <section className="hero-container">
        <div className={`hero-content ${isVisible ? 'fade-in' : ''}`}>
          <h1>GymForce</h1>
          <p>Tu viaje hacia la fuerza y la salud comienza aquí. Únete a nuestra comunidad.</p>
          
          <nav className="hero-nav">
            <Link href="/register" className="cta-button primary">Registrarse</Link>
            <Link href="/login" className="cta-button secondary">Iniciar sesión</Link>
          </nav>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <div className="container">
          <h2>¿Por qué elegirnos?</h2>
          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">💪</div>
              <h3>Equipamiento de primera</h3>
              <p>Máquinas y pesas de la más alta calidad para tu entrenamiento.</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">👨‍🏫</div>
              <h3>Entrenadores expertos</h3>
              <p>Profesionales certificados que te guiarán en tu proceso.</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">🔄</div>
              <h3>Rutinas personalizadas</h3>
              <p>Planes de entrenamiento adaptados a tus objetivos específicos.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Classes Section */}
      <section className="classes-section">
        <div className="container">
          <h2>Nuestras Clases</h2>
          <div className="classes-grid">
            <div className="class-card">
              <div className="class-image cardio"></div>
              <div className="class-content">
                <h3>Cardio Intenso</h3>
                <p>Mejora tu resistencia y quema calorías con nuestras sesiones de cardio.</p>
                <span>Lunes, Miércoles, Viernes - 18:00h</span>
              </div>
            </div>
            <div className="class-card">
              <div className="class-image strength"></div>
              <div className="class-content">
                <h3>Fuerza y Potencia</h3>
                <p>Desarrolla músculo y aumenta tu fuerza con entrenamiento especializado.</p>
                <span>Martes, Jueves - 19:00h</span>
              </div>
            </div>
            <div className="class-card">
              <div className="class-image yoga"></div>
              <div className="class-content">
                <h3>Yoga Fitness</h3>
                <p>Combina flexibilidad, equilibrio y fuerza mental.</p>
                <span>Sábados - 10:00h</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="testimonials-section">
        <div className="container">
          <h2>Lo que dicen nuestros miembros</h2>
          <div className="testimonials-grid">
            <div className="testimonial-card">
              {/* Error bash */}
              <p>&quot;En solo 3 meses he transformado mi cuerpo y ganado confianza. Los entrenadores son increíbles.&quot;</p>
              <div className="testimonial-author">
                <strong>Carlos M.</strong>
                <span>Miembro desde 2022</span>
              </div>
            </div>
            <div className="testimonial-card">
               {/* Error bash */}
              <p>&quot;El ambiente motivador y las instalaciones de primera hacen que siempre quiera volver.&quot;</p>
              <div className="testimonial-author">
                <strong>Ana L.</strong>
                <span>Miembro desde 2023</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="container">
          <h2>¿Listo para transformar tu vida?</h2>
          <p>Únete hoy mismo y obtén tu primera semana gratis</p>
          <Link href="/register" className="cta-button large">Comenzar ahora</Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="container">
          <div className="footer-content">
            <div className="footer-section">
              <h3>GymForce</h3>
              <p>Tu camino hacia una vida más fuerte y saludable.</p>
            </div>
            <div className="footer-section">
              <h4>Horario</h4>
              <p>Lunes a Viernes: 5:00 - 23:00</p>
              <p>Sábados y Domingos: 7:00 - 21:00</p>
            </div>
            <div className="footer-section">
              <h4>Contacto</h4>
              <p>info@gymforce.com</p>
              <p>+34 912 345 678</p>
            </div>
          </div>
          <div className="footer-bottom">
            <p>&copy; 2023 GymForce. Todos los derechos reservados.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}