import React, { useEffect, useRef, useState, useMemo } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { 
  Globe, 
  MapPin, 
  Crosshair, 
  Plus, 
  Minus, 
  Layers, 
  ArrowLeft, 
  ShieldAlert, 
  ExternalLink,
  Search,
  Building2,
  Server
} from 'lucide-react';

export interface ThreatLocationItem {
  id: string;
  ip: string;
  city: string;
  country: string;
  lat: number;
  lng: number;
  severity: string;
  severityLabel?: string;
  type?: string;
  simpleTitle: string;
  sender: string;
  subject?: string;
  threatScore: number;
  asn?: string;
  target?: string;
  targetCoords?: { lat: number; lng: number };
  status?: string;
  timestamp: string;
  plainSummary: string;
  summary?: string;
  isThreat?: boolean;
}

export type StreetMapLayer = 'dark' | 'satellite' | 'streets';

interface StreetMapViewProps {
  threat: ThreatLocationItem | null;
  allThreats: ThreatLocationItem[];
  onSelectThreat: (threat: ThreatLocationItem) => void;
  onReturnToOrbit: () => void;
  onOpenForensics?: () => void;
  initialLayer?: StreetMapLayer;
}

// Known Datacenter / Carrier Hotel Hubs for popular threat origins
const KNOWN_INFRASTRUCTURE: Record<string, { facility: string; street: string; asnType: string }> = {
  'frankfurt': { facility: 'DE-CIX Frankfurt & Equinix FR2', street: 'Hanauer Landstraße 322, Ostend', asnType: 'Tier-1 Internet Exchange Hub' },
  'kuala lumpur': { facility: 'AIMS Cyberjaya Datacenter', street: 'Jalan Tun Razak, Central Business District', asnType: 'Asia Gateway PoP' },
  'st. petersburg': { facility: 'Selectel Dubrovka Data Facility', street: 'Tsvetochnaya Ulitsa 21, Moskovsky District', asnType: 'Regional Autonomous Transit' },
  'amsterdam': { facility: 'AMS-IX & Equinix AM3 Science Park', street: 'Science Park 400, Watergraafsmeer', asnType: 'European Primary Interconnection' },
  'panama city': { facility: 'IFX Networks Panama PoP', street: 'Calle 50 & Avenida Balboa, Bella Vista', asnType: 'Offshore Hosting Infrastructure' },
  'san jose': { facility: 'Equinix SV1 Silicon Valley Exchange', street: '11 Great Oaks Blvd, San Jose, CA', asnType: 'US West Cloud Spine' },
  'new york': { facility: '111 8th Avenue Carrier Hotel', street: '111 8th Ave / Hudson St, Manhattan, NY', asnType: 'NYC Metro Interconnection' },
  'london': { facility: 'Telehouse North Docklands', street: 'Coriander Avenue, Poplar, London E14', asnType: 'LINX Gateway' },
  'tokyo': { facility: 'Equinix TY2 Tokyo Datacenter', street: 'Higashi-Shinagawa 2-Chome, Shinagawa-ku', asnType: 'JPIX Core Gateway' },
  'singapore': { facility: 'Equinix SG1 One-North', street: '20 Ayer Rajah Crescent, Queenstown', asnType: 'Southeast Asia Core PoP' }
};

export const StreetMapView: React.FC<StreetMapViewProps> = ({
  threat,
  allThreats,
  onSelectThreat,
  onReturnToOrbit,
  onOpenForensics,
  initialLayer = 'dark'
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const labelLayerRef = useRef<L.TileLayer | null>(null);
  const markersGroupRef = useRef<L.FeatureGroup | null>(null);
  const accuracyCircleRef = useRef<L.Circle | null>(null);

  const [activeLayer, setActiveLayer] = useState<StreetMapLayer>(initialLayer);
  const [currentZoom, setCurrentZoom] = useState<number>(15);
  const [searchQuery, setSearchQuery] = useState('');
  const [isLayerMenuOpen, setIsLayerMenuOpen] = useState(false);

  // Active coordinates
  const activeLat = (threat && typeof threat.lat === 'number' && Number.isFinite(threat.lat)) ? threat.lat : 50.1109;
  const activeLng = (threat && typeof threat.lng === 'number' && Number.isFinite(threat.lng)) ? threat.lng : 8.6821;
  const activeCityKey = threat?.city?.toLowerCase() || 'frankfurt';
  const infraInfo = KNOWN_INFRASTRUCTURE[activeCityKey] || {
    facility: 'ISP Edge Datacenter & Carrier Hub',
    street: `${threat?.city || 'City Center'}, Primary Telecommunications Sector`,
    asnType: threat?.asn || 'Autonomous System Network'
  };

  // Zoom description helper
  const getZoomDescription = (zoom: number): string => {
    if (zoom >= 18) return 'Building Footprints & Alleys (1:500)';
    if (zoom >= 16) return 'Street & Block Level (1:2,000)';
    if (zoom >= 14) return 'City District & Arteries (1:8,000)';
    if (zoom >= 11) return 'Metropolitan Area (1:30,000)';
    if (zoom >= 8) return 'Regional State Corridor';
    return 'Continental / Global Orbit';
  };

  // Tile configurations
  const getTileUrl = (layer: StreetMapLayer) => {
    switch (layer) {
      case 'dark':
        // CartoDB Dark Matter (High contrast cyber defense aesthetic)
        return 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
      case 'satellite':
        // Esri World Imagery (Real high-res aerial / satellite streets)
        return 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}';
      case 'streets':
        // OpenStreetMap Standard (Roads, buildings, landmarks)
        return 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
      default:
        return 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
    }
  };

  // Create High-Tech Pulsing DivIcon for threat pin
  const createThreatDivIcon = (item: ThreatLocationItem, isSelected: boolean) => {
    const score = item.threatScore ?? 0;
    const isCritical = score > 80;
    const isMild = score >= 50 && score <= 80;
    
    const colorBg = isCritical ? '#ef4444' : (isMild ? '#f97316' : '#10b981');
    const ringColor = isCritical ? 'rgba(239, 68, 68, 0.4)' : (isMild ? 'rgba(249, 115, 22, 0.4)' : 'rgba(16, 185, 129, 0.4)');
    const scale = isSelected ? 'scale(1.2)' : 'scale(1.0)';
    const zIndex = isSelected ? 1000 : 500;

    return L.divIcon({
      className: 'threat-custom-marker',
      html: `
        <div style="position:relative; width:36px; height:36px; display:flex; align-items:center; justify-content:center; transform:${scale}; z-index:${zIndex};">
          <div style="position:absolute; inset:0; border-radius:50%; background:${ringColor}; animation:threatPing 2s cubic-bezier(0,0,0.2,1) infinite;"></div>
          <div style="position:absolute; width:22px; height:22px; border-radius:50%; background:#090d16; border:2px solid ${colorBg}; display:flex; align-items:center; justify-content:center; box-shadow:0 0 12px ${colorBg};">
            <div style="width:8px; height:8px; border-radius:50%; background:${colorBg};"></div>
          </div>
          ${isSelected ? `
            <div style="position:absolute; bottom:-18px; left:50%; transform:translateX(-50%); background:#090d16; color:${colorBg}; border:1px solid ${colorBg}; padding:1px 6px; border-radius:4px; font-size:9px; font-family:monospace; font-weight:bold; white-space:nowrap; box-shadow:0 2px 6px rgba(0,0,0,0.6);">
              ${score}/100
            </div>
          ` : ''}
        </div>
      `,
      iconSize: [36, 36],
      iconAnchor: [18, 18],
      popupAnchor: [0, -18]
    });
  };

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;
    if (mapInstanceRef.current) return;

    // Create Leaflet map instance with robust finite coordinates
    const initialLat = Number.isFinite(activeLat) ? activeLat : 50.1109;
    const initialLng = Number.isFinite(activeLng) ? activeLng : 8.6821;

    const map = L.map(mapContainerRef.current, {
      center: [initialLat, initialLng],
      zoom: 15,
      minZoom: 3,
      maxZoom: 19,
      zoomControl: false, // Custom zoom HUD
      attributionControl: false
    });

    mapInstanceRef.current = map;

    // Add Base Tile Layer
    const baseLayer = L.tileLayer(getTileUrl(activeLayer), {
      maxZoom: 19,
      subdomains: activeLayer === 'streets' ? ['a', 'b', 'c'] : ['a', 'b', 'c', 'd']
    });
    baseLayer.addTo(map);
    tileLayerRef.current = baseLayer;

    // If satellite mode, add street labels overlay
    if (activeLayer === 'satellite') {
      const labels = L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager_only_labels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        opacity: 0.85
      });
      labels.addTo(map);
      labelLayerRef.current = labels;
    }

    // Feature group for markers
    const markersGroup = L.featureGroup().addTo(map);
    markersGroupRef.current = markersGroup;

    // Listen to zoom events to update HUD
    map.on('zoomend', () => {
      const z = map.getZoom();
      setCurrentZoom(z);
    });

    // Handle map resize cleanly
    const resizeObserver = new ResizeObserver(() => {
      map.invalidateSize();
    });
    resizeObserver.observe(mapContainerRef.current);

    return () => {
      resizeObserver.disconnect();
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update Tile Layer when activeLayer changes
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
    }
    if (labelLayerRef.current) {
      map.removeLayer(labelLayerRef.current);
      labelLayerRef.current = null;
    }

    const newBase = L.tileLayer(getTileUrl(activeLayer), {
      maxZoom: 19,
      subdomains: activeLayer === 'streets' ? ['a', 'b', 'c'] : ['a', 'b', 'c', 'd']
    });
    newBase.addTo(map);
    tileLayerRef.current = newBase;

    // In satellite mode, overlay street names and building outlines
    if (activeLayer === 'satellite') {
      const labels = L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager_only_labels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        opacity: 0.85
      });
      labels.addTo(map);
      labelLayerRef.current = labels;
    }
  }, [activeLayer]);

  // Update Markers & Fly to active threat
  useEffect(() => {
    const map = mapInstanceRef.current;
    const markersGroup = markersGroupRef.current;
    if (!map || !markersGroup) return;

    markersGroup.clearLayers();

    // Accuracy uncertainty circle around active threat
    if (accuracyCircleRef.current) {
      map.removeLayer(accuracyCircleRef.current);
      accuracyCircleRef.current = null;
    }

    if (threat) {
      const targetLat = Number.isFinite(threat.lat) ? threat.lat : 50.1109;
      const targetLng = Number.isFinite(threat.lng) ? threat.lng : 8.6821;
      const score = threat.threatScore ?? 0;
      const strokeColor = score > 80 ? '#ef4444' : (score >= 50 ? '#f97316' : '#10b981');

      const circle = L.circle([targetLat, targetLng], {
        radius: 650, // 650m estimated ISP subnet range
        color: strokeColor,
        weight: 1.5,
        opacity: 0.7,
        fillColor: strokeColor,
        fillOpacity: 0.12,
        dashArray: '4, 6'
      }).addTo(map);

      accuracyCircleRef.current = circle;

      // Smooth camera pan and deep zoom into streets
      map.flyTo([targetLat, targetLng], 16, {
        duration: 1.2,
        easeLinearity: 0.25
      });
    }

    // Add markers for all threats
    allThreats.forEach((item) => {
      if (!item || !Number.isFinite(item.lat) || !Number.isFinite(item.lng)) return;
      const isSelected = item.id === threat?.id;
      const marker = L.marker([item.lat, item.lng], {
        icon: createThreatDivIcon(item, isSelected),
        zIndexOffset: isSelected ? 1000 : 100
      });

      // Interactive popup
      const score = item.threatScore ?? 0;
      const scoreBg = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');
      
      const popupContent = document.createElement('div');
      popupContent.className = 'threat-popup-wrapper text-slate-900 font-sans';
      popupContent.innerHTML = `
        <div style="min-width: 210px; padding: 4px 0;">
          <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom: 6px;">
            <strong style="font-size: 13px; color: #0f172a;">${item.city}, ${item.country}</strong>
            <span style="font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px; color: white; background: ${score > 80 ? '#ef4444' : (score >= 50 ? '#f97316' : '#10b981')}">
              ${score}/100
            </span>
          </div>
          <p style="font-size: 11px; color: #64748b; margin: 0 0 6px 0; font-family: monospace;">${item.sender}</p>
          <div style="font-size: 10px; color: #475569; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px; margin-bottom: 8px;">
            <div><strong>IP:</strong> <span style="font-family: monospace;">${item.ip}</span></div>
            <div><strong>ASN:</strong> <span style="font-family: monospace;">${item.asn || 'AS-DIRECT'}</span></div>
            <div><strong>Coordinates:</strong> ${item.lat.toFixed(4)}°, ${item.lng.toFixed(4)}°</div>
          </div>
          <button id="popup-inspect-btn-${item.id}" style="width: 100%; background: #6366f1; color: white; border: none; padding: 6px 10px; border-radius: 6px; font-size: 11px; font-weight: bold; cursor: pointer;">
            Deep Forensics Inspection
          </button>
        </div>
      `;

      marker.bindPopup(popupContent, { maxWidth: 280 });

      marker.on('popupopen', () => {
        const btn = document.getElementById(`popup-inspect-btn-${item.id}`);
        if (btn && onOpenForensics) {
          btn.onclick = () => onOpenForensics();
        }
      });

      marker.on('click', () => {
        onSelectThreat(item);
      });

      markersGroup.addLayer(marker);
    });
  }, [threat, allThreats]);

  // Zoom Controls Handlers
  const handleZoomIn = () => {
    if (!mapInstanceRef.current) return;
    mapInstanceRef.current.zoomIn(1);
  };

  const handleZoomOut = () => {
    if (!mapInstanceRef.current) return;
    const current = mapInstanceRef.current.getZoom();
    if (current <= 4) {
      // Return to planetary orbit when zooming all the way out
      onReturnToOrbit();
    } else {
      mapInstanceRef.current.zoomOut(1);
    }
  };

  const handleRecenter = () => {
    if (!mapInstanceRef.current || !threat) return;
    mapInstanceRef.current.flyTo([threat.lat, threat.lng], 16, { duration: 0.8 });
  };

  // Search filtering
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = searchQuery.toLowerCase();
    return allThreats.filter(t => 
      t.city.toLowerCase().includes(q) ||
      t.country.toLowerCase().includes(q) ||
      t.ip.toLowerCase().includes(q) ||
      t.sender.toLowerCase().includes(q)
    );
  }, [allThreats, searchQuery]);

  return (
    <div className="relative w-full h-[460px] bg-slate-950 overflow-hidden rounded-b-2xl">
      {/* Embedded Leaflet Map Container */}
      <div ref={mapContainerRef} className="w-full h-full z-0" />

      {/* CSS Animation for Ping */}
      <style>{`
        @keyframes threatPing {
          0% { transform: scale(0.8); opacity: 0.8; }
          70% { transform: scale(2.4); opacity: 0; }
          100% { transform: scale(2.4); opacity: 0; }
        }
        .leaflet-container {
          background: #090d16 !important;
          outline: none;
        }
        .leaflet-popup-content-wrapper {
          background: #ffffff !important;
          border-radius: 12px !important;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5) !important;
        }
      `}</style>

      {/* Top Left: Return to Planetary Orbit Button & Breadcrumb */}
      <div className="absolute left-4 top-4 z-20 flex items-center gap-2">
        <button
          onClick={onReturnToOrbit}
          title="Return to 3D Planetary Orbit"
          className="bg-slate-900/90 hover:bg-indigo-600 text-white border border-slate-700/80 hover:border-indigo-500 rounded-xl px-3 py-2 text-xs font-bold shadow-xl backdrop-blur-md flex items-center gap-2 transition-all cursor-pointer group"
        >
          <ArrowLeft className="w-4 h-4 text-indigo-400 group-hover:text-white transition-colors" />
          <Globe className="w-3.5 h-3.5 text-indigo-400 group-hover:text-white transition-colors" />
          <span>Planetary Orbit</span>
        </button>

        {/* Street Level Active Badge */}
        <div className="bg-slate-900/90 border border-slate-700/80 text-white rounded-xl px-3 py-2 text-xs font-mono shadow-xl backdrop-blur-md hidden sm:flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-bold text-slate-200">Street Radar Active</span>
          <span className="text-slate-500">|</span>
          <span className="text-indigo-400">{getZoomDescription(currentZoom)}</span>
        </div>
      </div>

      {/* Top Right: Tile Layer Switcher Pill */}
      <div className="absolute right-4 top-4 z-20 bg-slate-900/90 backdrop-blur-md border border-slate-700/80 rounded-xl p-1 flex items-center gap-1 shadow-xl">
        <button
          onClick={() => setActiveLayer('satellite')}
          title="High-Resolution Satellite Aerial Streets"
          className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
            activeLayer === 'satellite' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
          }`}
        >
          <span>🛰️ Satellite</span>
        </button>
        <button
          onClick={() => setActiveLayer('dark')}
          title="Cyber Defense Dark Street Map"
          className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
            activeLayer === 'dark' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
          }`}
        >
          <span>🌃 Dark Streets</span>
        </button>
        <button
          onClick={() => setActiveLayer('streets')}
          title="Standard Detailed Roads & Buildings"
          className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
            activeLayer === 'streets' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
          }`}
        >
          <span>🗺️ Roads & Vector</span>
        </button>
      </div>

      {/* Bottom Left: Street-Level Infrastructure Card */}
      {threat && (
        <div className="absolute left-4 bottom-4 z-20 bg-slate-900/95 border border-slate-700/80 text-white rounded-xl p-3 shadow-2xl backdrop-blur-md max-w-sm">
          <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-slate-800">
            <div className="flex items-center gap-1.5">
              <Building2 className="w-3.5 h-3.5 text-indigo-400" />
              <span className="text-[11px] font-bold text-slate-100">{threat.city}, {threat.country}</span>
            </div>
            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
              threat.threatScore > 80 ? 'bg-red-900/80 text-red-200 border border-red-700' : 'bg-emerald-900/80 text-emerald-200 border border-emerald-700'
            }`}>
              {threat.threatScore}/100 Risk
            </span>
          </div>

          <div className="mt-2 space-y-1 text-[11px]">
            <div className="flex items-start gap-1.5 text-slate-300">
              <MapPin className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
              <span className="truncate">{infraInfo.street}</span>
            </div>

            <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[10px]">
              <Server className="w-3 h-3 text-cyan-400 shrink-0" />
              <span className="truncate">{infraInfo.facility}</span>
            </div>

            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-800">
              <span>IP: <strong className="text-slate-200">{threat.ip}</strong></span>
              <span>GPS: <strong className="text-slate-200">{threat.lat.toFixed(4)}°, {threat.lng.toFixed(4)}°</strong></span>
            </div>
          </div>
        </div>
      )}

      {/* Bottom Right: Interactive Zoom & Pan HUD */}
      <div className="absolute right-4 bottom-4 z-20 flex flex-col gap-1.5">
        <button
          onClick={handleZoomIn}
          title="Zoom In Deeper (Up to Level 19 Building Footprints)"
          className="w-8 h-8 bg-slate-900/90 hover:bg-indigo-600 text-white rounded-lg shadow-md border border-slate-700 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
        >
          <Plus className="w-4 h-4" />
        </button>
        <button
          onClick={handleZoomOut}
          title={currentZoom <= 4 ? "Zoom out back to 3D Orbit" : "Zoom Out"}
          className="w-8 h-8 bg-slate-900/90 hover:bg-indigo-600 text-white rounded-lg shadow-md border border-slate-700 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
        >
          <Minus className="w-4 h-4" />
        </button>
        <button
          onClick={handleRecenter}
          title="Recenter on Attacker Coordinates"
          className="w-8 h-8 bg-slate-900/90 hover:bg-indigo-600 text-white rounded-lg shadow-md border border-slate-700 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
        >
          <Crosshair className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onReturnToOrbit}
          title="Switch to 3D Earth Globe"
          className="w-8 h-8 bg-indigo-600/90 hover:bg-indigo-700 text-white rounded-lg shadow-md border border-indigo-500 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
        >
          <Globe className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Orbit zoom hint when user zooms out */}
      {currentZoom <= 4 && (
        <div 
          onClick={onReturnToOrbit}
          className="absolute top-16 left-1/2 -translate-x-1/2 z-20 bg-indigo-600/95 text-white border border-indigo-400 px-4 py-1.5 rounded-full text-xs font-bold shadow-2xl backdrop-blur-md cursor-pointer animate-bounce flex items-center gap-2"
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Zooming out? Click to return to 3D Planetary Orbit 🌍</span>
        </div>
      )}
    </div>
  );
};
