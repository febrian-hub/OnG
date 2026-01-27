/**
 * FeatureCard Component
 * 
 * Reusable card component for displaying feature modules
 */

import React from 'react';
import './Dashboard.css';

export interface FeatureCardProps {
  icon: React.ReactNode;
  iconBgClass: string;
  label: string;
  title: string;
  description: string;
  features: Array<{
    color: string;
    text: string;
  }>;
  onLaunch?: () => void;
}

export const FeatureCard: React.FC<FeatureCardProps> = ({
  icon,
  iconBgClass,
  label,
  title,
  description,
  features,
  onLaunch
}) => {
  return (
    <div className="feature-card">
      <div className="feature-card__header">
        <div className={`feature-card__icon ${iconBgClass}`}>
          {icon}
        </div>
        <div className="feature-card__title-group">
          <span className="feature-card__label">{label}</span>
          <h3 className="feature-card__title">{title}</h3>
        </div>
      </div>

      <p className="feature-card__description">{description}</p>

      <ul className="feature-card__features">
        {features.map((feature, index) => (
          <li key={index} className="feature-card__feature">
            <span 
              className="feature-card__feature-dot" 
              style={{ backgroundColor: feature.color }}
            />
            {feature.text}
          </li>
        ))}
      </ul>

      <button className="feature-card__button" onClick={onLaunch}>
        <span>Launch Module</span>
        <svg 
          className="feature-card__button-arrow" 
          viewBox="0 0 24 24" 
          fill="none" 
          stroke="currentColor" 
          strokeWidth="2"
        >
          <path d="M5 12h14M12 5l7 7-7 7" />
        </svg>
      </button>
    </div>
  );
};

export default FeatureCard;
