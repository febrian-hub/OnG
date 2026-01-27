/**
 * ProfileSidebar Component
 * 
 * Sidebar displaying profile information and CV
 */

import React from 'react';
import './Sidebar.css';

export const ProfileSidebar: React.FC = () => {
  return (
    <aside className="profile-sidebar">
      {/* Profile Header */}
      <div className="profile-sidebar__header">
        <div className="profile-sidebar__avatar">
          <span className="profile-sidebar__avatar-text">FI</span>
        </div>
        <h2 className="profile-sidebar__name">Febrian Ibrahim</h2>
      </div>

      {/* Contact Info */}
      <div className="profile-sidebar__section">
        <div className="profile-sidebar__contact">
          <div className="profile-sidebar__contact-item">
            <svg className="profile-sidebar__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
            <span className="profile-sidebar__contact-text">febrianbrhm@gmail.com</span>
          </div>
          <div className="profile-sidebar__contact-item">
            <svg className="profile-sidebar__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z"/>
            </svg>
            <span className="profile-sidebar__contact-text">+6285210893163</span>
          </div>
          <div className="profile-sidebar__contact-item">
            <svg className="profile-sidebar__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M16 8a6 6 0 016 6v7h-4v-7a2 2 0 00-2-2 2 2 0 00-2 2v7h-4v-7a6 6 0 016-6zM2 9h4v12H2z"/>
              <circle cx="4" cy="4" r="2"/>
            </svg>
            <a href="https://www.linkedin.com/in/febrian-ibrahim/" target="_blank" rel="noopener noreferrer" className="profile-sidebar__link">
              LinkedIn Profile
            </a>
          </div>
        </div>
      </div>

      {/* About */}
      <div className="profile-sidebar__section">
        <h3 className="profile-sidebar__section-title">
          <svg className="profile-sidebar__section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
          IoT & Automation Eng.
        </h3>
        <p className="profile-sidebar__text">
          Experienced automation & IoT professional with 3+ years hands-on experience in industrial design, PLC Programming, and IoT development.
        </p>
      </div>

      {/* Education */}
      <div className="profile-sidebar__section">
        <h3 className="profile-sidebar__section-title">
          <svg className="profile-sidebar__section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 10v6M2 10l10-5 10 5-10 5z"/>
            <path d="M6 12v5c3 3 9 3 12 0v-5"/>
          </svg>
          Education
        </h3>
        <div className="profile-sidebar__item">
          <div className="profile-sidebar__item-title">ITS Surabaya</div>
          <div className="profile-sidebar__item-subtitle">Automation Electrical Eng.</div>
          <div className="profile-sidebar__item-meta">GPA: 3.11 | 2018 - 2023</div>
        </div>
      </div>

      {/* Publication */}
      <div className="profile-sidebar__section">
        <h3 className="profile-sidebar__section-title">
          <svg className="profile-sidebar__section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/>
          </svg>
          Publication
        </h3>
        <ul className="profile-sidebar__list">
          <li>Visual Inspection System Gear Surface Defects (Faster RCNN)</li>
        </ul>
      </div>

      {/* Arsenal/Skills */}
      <div className="profile-sidebar__section">
        <h3 className="profile-sidebar__section-title">
          <svg className="profile-sidebar__section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
            <path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/>
          </svg>
          Arsenal
        </h3>
        <div className="profile-sidebar__tags">
          <span className="profile-sidebar__tag">Node.js</span>
          <span className="profile-sidebar__tag">React</span>
          <span className="profile-sidebar__tag">PostgreSQL</span>
          <span className="profile-sidebar__tag">Docker</span>
          <span className="profile-sidebar__tag">PLC</span>
          <span className="profile-sidebar__tag">Modbus</span>
          <span className="profile-sidebar__tag">Wireshark</span>
          <span className="profile-sidebar__tag">ELK Stack</span>
        </div>
      </div>

      {/* Contact Button */}
      <div className="profile-sidebar__footer">
        <button className="profile-sidebar__contact-btn">
          <svg className="profile-sidebar__btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
          </svg>
          Contact
        </button>
        <a 
          href="https://www.linkedin.com/in/febrian-ibrahim/" 
          target="_blank" 
          rel="noopener noreferrer"
          className="profile-sidebar__linkedin-btn"
        >
          <svg className="profile-sidebar__btn-icon" viewBox="0 0 24 24" fill="currentColor">
            <path d="M16 8a6 6 0 016 6v7h-4v-7a2 2 0 00-2-2 2 2 0 00-2 2v7h-4v-7a6 6 0 016-6zM2 9h4v12H2z"/>
            <circle cx="4" cy="4" r="2"/>
          </svg>
          LinkedIn
        </a>
      </div>
    </aside>
  );
};

export default ProfileSidebar;
