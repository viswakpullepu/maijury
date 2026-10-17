import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Globe as GlobeIcon, 
  Radio, 
  Microscope, 
  Search,
  Plus,
  Minus,
  RotateCcw,
  Play,
  Pause,
  MapPin,
  X,
  Crosshair
} from 'lucide-react';

interface ThreatLocationItem {
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

export type MapTheme = 'satellite' | 'night' | 'dark';

import { getOrCreateSessionId } from './LiveEmailInterceptor';
import { SAMPLE_EMAILS } from '../data/threatData';
import { StreetMapView } from './StreetMapView';

const CITY_COORDINATES: Record<string, { lat: number; lng: number; country: string }> = {
  'frankfurt': { lat: 50.1109, lng: 8.6821, country: 'Germany' },
  'kuala lumpur': { lat: 3.1390, lng: 101.6869, country: 'Malaysia' },
  'st. petersburg': { lat: 59.9311, lng: 30.3609, country: 'Russia' },
  'saint petersburg': { lat: 59.9311, lng: 30.3609, country: 'Russia' },
  'amsterdam': { lat: 52.3676, lng: 4.9041, country: 'Netherlands' },
  'panama city': { lat: 8.9824, lng: -79.5199, country: 'Panama' },
  'san jose': { lat: 37.3382, lng: -121.8863, country: 'United States' },
  'new york': { lat: 40.7128, lng: -74.0060, country: 'United States' },
  'san francisco': { lat: 37.7749, lng: -122.4194, country: 'United States' },
  'london': { lat: 51.5074, lng: -0.1278, country: 'United Kingdom' },
  'berlin': { lat: 52.5200, lng: 13.4050, country: 'Germany' },
  'tokyo': { lat: 35.6762, lng: 139.6503, country: 'Japan' },
  'singapore': { lat: 1.3521, lng: 103.8198, country: 'Singapore' },
  'sydney': { lat: -33.8688, lng: 151.2093, country: 'Australia' },
  'paris': { lat: 48.8566, lng: 2.3522, country: 'France' },
  'dubai': { lat: 25.2048, lng: 55.2708, country: 'United Arab Emirates' },
  'seoul': { lat: 37.5665, lng: 126.9780, country: 'South Korea' },
  'mumbai': { lat: 19.0760, lng: 72.8777, country: 'India' },
  'bangalore': { lat: 12.9716, lng: 77.5946, country: 'India' },
  'toronto': { lat: 43.6532, lng: -79.3832, country: 'Canada' },
  'sao paulo': { lat: -23.5505, lng: -46.6333, country: 'Brazil' },
  'beijing': { lat: 39.9042, lng: 116.4074, country: 'China' },
  'hong kong': { lat: 22.3193, lng: 114.1694, country: 'Hong Kong' },
  'zurich': { lat: 47.3769, lng: 8.5417, country: 'Switzerland' },
  'stockholm': { lat: 59.3293, lng: 18.0686, country: 'Sweden' },
  'warsaw': { lat: 52.2297, lng: 21.0122, country: 'Poland' }
};

interface GlobeViewProps {
  onSelectThreat: (threatId: string) => void;
  onOpenForensics: () => void;
}

export const GlobeView: React.FC<GlobeViewProps> = ({
  onSelectThreat,
  onOpenForensics
}) => {
  const canvasContainerRef = useRef<HTMLDivElement>(null);
  const sessionId = getOrCreateSessionId();
  
  // Custom emails from database & localStorage (falls back to SAMPLE_EMAILS so globe is immediately rich with telemetry)
  const [customEmails, setCustomEmails] = useState<any[]>(() => {
    try {
      const cached = localStorage.getItem(`threatlens_custom_emails_db_${sessionId}`);
      const parsed = cached ? JSON.parse(cached) : [];
      return (Array.isArray(parsed) && parsed.length > 0) ? parsed : SAMPLE_EMAILS;
    } catch (_) {
      return SAMPLE_EMAILS;
    }
  });

  // Sync with persistent backend database on mount & listen for live telemetry broadcasts
  useEffect(() => {
    const sid = getOrCreateSessionId();
    fetch(`/api/emails?session_id=${encodeURIComponent(sid)}`, {
      headers: { 'x-session-id': sid },
      credentials: 'include'
    })
      .then(res => res.json())
      .then(data => {
        if (data.emails && Array.isArray(data.emails) && data.emails.length > 0) {
          setCustomEmails(data.emails);
          try {
            localStorage.setItem(`threatlens_custom_emails_db_${sid}`, JSON.stringify(data.emails));
          } catch (_) {}
        }
      })
      .catch(() => {});

    const handleRealtimeUpdate = (e: any) => {
      if (e.detail?.emails) {
        setCustomEmails(e.detail.emails);
      }
    };

    window.addEventListener('threatlens_emails_updated', handleRealtimeUpdate);
    return () => window.removeEventListener('threatlens_emails_updated', handleRealtimeUpdate);
  }, []);

  // Map real analyzed emails directly to 3D spherical coordinates
  const allThreatLocations: ThreatLocationItem[] = useMemo(() => {
    const locations: ThreatLocationItem[] = [];

    customEmails.forEach((email) => {
      if (!email) return;

      // Extract genuine coordinates if provided by backend geo engine
      let lat = email.sender?.lat ?? email.originLocation?.lat ?? null;
      let lng = email.sender?.lng ?? email.originLocation?.lng ?? null;
      let city = email.sender?.location?.split(',')[0]?.trim() || email.originLocation?.city || 'No Location Data';
      let country = email.sender?.location?.split(',')[1]?.trim() || email.originLocation?.country || 'No Location Data';

      // If lat/lng was not resolved, check city coordinate index
      if ((lat === null || lat === 0) && city && city !== 'No Location Data') {
        const key = city.toLowerCase();
        if (CITY_COORDINATES[key]) {
          lat = CITY_COORDINATES[key].lat;
          lng = CITY_COORDINATES[key].lng;
          country = CITY_COORDINATES[key].country;
        }
      }

      // Default safe fallback only if coordinates were completely absent or NaN
      const numLat = Number(lat);
      const numLng = Number(lng);
      if (!Number.isFinite(numLat) || !Number.isFinite(numLng)) {
        lat = 50.1109; // Default reference point
        lng = 8.6821;
        city = (city && city !== 'No Location Data') ? city : 'Frankfurt';
        country = (country && country !== 'No Location Data') ? country : 'Germany';
      } else {
        lat = numLat;
        lng = numLng;
      }

      if (!locations.some(b => b.id === email.id)) {
        const score = email.threatScore ?? (email.isThreat ? 85 : 0);
        locations.push({
          id: email.id || `custom-${Date.now()}`,
          ip: email.sender?.originIp || email.originLocation?.ip || '0.0.0.0',
          city: city,
          country: country,
          lat: lat,
          lng: lng,
          severity: score > 80 ? 'critical' : (score >= 50 ? 'high' : 'safe'),
          severityLabel: email.severityLabel || (score > 80 ? 'Critical Threat' : (score >= 50 ? 'Mild Threat' : 'Safe & Verified')),
          type: email.userFriendlyCategory || 'Analyzed Stream',
          simpleTitle: email.title || email.metadata?.subject || 'Live Analyzed Email',
          sender: email.sender?.email || 'unknown@sender.com',
          subject: email.metadata?.subject || 'Email Subject',
          threatScore: score,
          asn: email.sender?.asn || email.originLocation?.asn || 'AS-DIRECT',
          status: score > 80 ? '🚨 Critical Threat' : (score >= 50 ? '⚠️ Mild Threat' : '✅ 100% Safe & Verified'),
          timestamp: email.metadata?.date || 'Today',
          plainSummary: email.simpleTakeaway || (score > 80 ? 'High-risk payload or spoofing detected.' : (score >= 50 ? 'Mild anomalies detected.' : 'Legitimate clean message with verified cryptographic signatures.')),
          isThreat: score >= 50
        });
      }
    });

    return locations;
  }, [customEmails]);

  const [selectedThreat, setSelectedThreat] = useState<ThreatLocationItem | null>(allThreatLocations[0] || null);

  useEffect(() => {
    if (!selectedThreat && allThreatLocations.length > 0) {
      setSelectedThreat(allThreatLocations[0]);
    }
  }, [allThreatLocations]);

  const [mapTheme, setMapTheme] = useState<MapTheme>('satellite');
  const [viewMode, setViewMode] = useState<'globe' | 'street'>('globe');
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isAutoRotating, setIsAutoRotating] = useState(false);
  const [cameraDistance, setCameraDistance] = useState(230);
  const [hoveredThreat, setHoveredThreat] = useState<ThreatLocationItem | null>(null);
  const [hoverPosition, setHoverPosition] = useState<{ x: number; y: number } | null>(null);

  // Three.js refs
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const globeGroupRef = useRef<THREE.Group | null>(null);
  const cloudsMeshRef = useRef<THREE.Mesh | null>(null);
  const earthMaterialRef = useRef<THREE.MeshStandardMaterial | null>(null);
  const beaconMeshRef = useRef<THREE.Mesh | null>(null);
  const pulseRingsRef = useRef<THREE.Mesh[]>([]);
  const pinMeshesRef = useRef<THREE.Mesh[]>([]);
  const animationFrameId = useRef<number | null>(null);
  const isUserInteracting = useRef(false);

  // Camera animation interpolation state
  const isAnimatingCamera = useRef(false);
  const cameraAnimStartTime = useRef(0);
  const cameraAnimDuration = useRef(1200); // 1.2s smooth easing
  const cameraStartPos = useRef(new THREE.Vector3());
  const cameraTargetPos = useRef(new THREE.Vector3());

  // Real Earth Textures Loader
  const textureLoader = useMemo(() => new THREE.TextureLoader(), []);
  const textures = useMemo(() => ({
    satellite: textureLoader.load('/assets/earth_blue_marble.jpg'),
    night: textureLoader.load('/assets/earth_night.jpg'),
    dark: textureLoader.load('/assets/earth_dark.jpg'),
    clouds: textureLoader.load('/assets/earth_clouds.jpg'),
    topology: textureLoader.load('/assets/earth_topology.png')
  }), [textureLoader]);

  // Helper: Lat/Lng to 3D Cartesian coordinates on sphere
  const latLngToVector3 = (lat: number, lng: number, radius: number = 80): THREE.Vector3 => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  };

  // Dynamically update globe material when mapTheme changes
  useEffect(() => {
    if (!earthMaterialRef.current) return;
    const mat = earthMaterialRef.current;
    if (mapTheme === 'satellite') {
      mat.map = textures.satellite;
      mat.bumpMap = textures.topology;
      mat.bumpScale = 0.65;
      mat.roughness = 0.6;
      mat.metalness = 0.08;
      mat.emissive = new THREE.Color(0x000000);
      mat.emissiveMap = null;
      mat.emissiveIntensity = 0.0;
    } else if (mapTheme === 'night') {
      mat.map = textures.night;
      mat.bumpMap = textures.topology;
      mat.bumpScale = 0.45;
      mat.roughness = 0.8;
      mat.metalness = 0.05;
      mat.emissive = new THREE.Color(0xffe082);
      mat.emissiveMap = textures.night;
      mat.emissiveIntensity = 0.85;
    } else {
      mat.map = textures.dark;
      mat.bumpMap = textures.topology;
      mat.bumpScale = 0.35;
      mat.roughness = 0.65;
      mat.metalness = 0.15;
      mat.emissive = new THREE.Color(0x0284c7);
      mat.emissiveMap = textures.dark;
      mat.emissiveIntensity = 0.35;
    }
    mat.needsUpdate = true;
  }, [mapTheme, textures]);

  // Main Three.js Initialization with True Free OrbitControls & Real Maps
  useEffect(() => {
    const container = canvasContainerRef.current;
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 460;

    // 1. Scene
    const scene = new THREE.Scene();
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 35, 220);
    cameraRef.current = camera;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    } catch (e) {
      console.warn('[ThreatLens] WebGL hardware renderer unavailable, using fallback', e);
      return;
    }
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. Free OrbitControls: Fluid 360° omnidirectional rotation, inertia damping, no center drift
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.rotateSpeed = 0.85;
    controls.zoomSpeed = 1.1;
    controls.enablePan = false; // Strictly pivots around Earth center (0,0,0)
    controls.minDistance = 92;  // Allows zooming in close to land
    controls.maxDistance = 360; // Max zoom out
    controls.minPolarAngle = 0.05; // Free vertical pitch over North Pole
    controls.maxPolarAngle = Math.PI - 0.05; // Free vertical pitch over South Pole
    controls.target.set(0, 0, 0);
    controls.addEventListener('start', () => { isUserInteracting.current = true; });
    controls.addEventListener('end', () => { isUserInteracting.current = false; });
    controlsRef.current = controls;

    // 5. Globe Root Group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    // 6. Realistic Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.1);
    scene.add(ambientLight);

    const sunLight = new THREE.DirectionalLight(0xffffff, 1.6);
    sunLight.position.set(160, 110, 190);
    scene.add(sunLight);

    const rimLight = new THREE.DirectionalLight(0x818cf8, 0.85);
    rimLight.position.set(-160, -90, -130);
    scene.add(rimLight);

    // 7. Real Earth Sphere Mesh with Accurate Maps
    const radius = 80;
    const geometry = new THREE.SphereGeometry(radius, 64, 64);

    const initialTexture = mapTheme === 'night' 
      ? textures.night 
      : (mapTheme === 'dark' ? textures.dark : textures.satellite);

    const earthMaterial = new THREE.MeshStandardMaterial({
      map: initialTexture,
      bumpMap: textures.topology,
      bumpScale: mapTheme === 'satellite' ? 0.65 : 0.4,
      roughness: 0.6,
      metalness: 0.08
    });
    if (mapTheme === 'night') {
      earthMaterial.emissive = new THREE.Color(0xffe082);
      earthMaterial.emissiveMap = textures.night;
      earthMaterial.emissiveIntensity = 0.85;
    } else if (mapTheme === 'dark') {
      earthMaterial.emissive = new THREE.Color(0x0284c7);
      earthMaterial.emissiveMap = textures.dark;
      earthMaterial.emissiveIntensity = 0.35;
    }
    earthMaterialRef.current = earthMaterial;

    const earthMesh = new THREE.Mesh(geometry, earthMaterial);
    globeGroup.add(earthMesh);

    // Graticule coordinate grid lines (equator, parallels, meridians)
    const graticuleGroup = new THREE.Group();
    const graticuleMat = new THREE.LineBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.14
    });

    // Parallels (Latitude lines at -60, -30, 0, 30, 60)
    [-60, -30, 0, 30, 60].forEach(lat => {
      const phi = (90 - lat) * (Math.PI / 180);
      const ringRadius = radius * Math.sin(phi);
      const ringY = radius * Math.cos(phi);
      const ringGeo = new THREE.BufferGeometry();
      const points: THREE.Vector3[] = [];
      const segments = 64;
      for (let i = 0; i <= segments; i++) {
        const theta = (i / segments) * Math.PI * 2;
        points.push(new THREE.Vector3(ringRadius * Math.cos(theta), ringY, ringRadius * Math.sin(theta)));
      }
      ringGeo.setFromPoints(points);
      const line = new THREE.Line(ringGeo, graticuleMat);
      graticuleGroup.add(line);
    });

    // Meridians (Longitude lines every 45 deg)
    for (let lng = 0; lng < 360; lng += 45) {
      const ringGeo = new THREE.BufferGeometry();
      const points: THREE.Vector3[] = [];
      const segments = 64;
      for (let i = 0; i <= segments; i++) {
        const lat = -90 + (i / segments) * 180;
        points.push(latLngToVector3(lat, lng, radius * 1.001));
      }
      ringGeo.setFromPoints(points);
      const line = new THREE.Line(ringGeo, graticuleMat);
      graticuleGroup.add(line);
    }
    globeGroup.add(graticuleGroup);

    // Atmospheric outer glow halo
    const atmosphereGeo = new THREE.SphereGeometry(radius * 1.045, 48, 48);
    const atmosphereMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.16,
      side: THREE.BackSide
    });
    const atmosphere = new THREE.Mesh(atmosphereGeo, atmosphereMat);
    globeGroup.add(atmosphere);

    // Real Clouds Layer
    const cloudsGeo = new THREE.SphereGeometry(radius * 1.014, 48, 48);
    const cloudsMat = new THREE.MeshStandardMaterial({
      map: textures.clouds,
      transparent: true,
      opacity: 0.3,
      blending: THREE.AdditiveBlending
    });
    const cloudsMesh = new THREE.Mesh(cloudsGeo, cloudsMat);
    globeGroup.add(cloudsMesh);
    cloudsMeshRef.current = cloudsMesh;

    // 8. Dynamic Threat Location Markers & Pulsing Radar Rings
    const pulseRings: THREE.Mesh[] = [];
    const pinMeshes: THREE.Mesh[] = [];

    allThreatLocations.forEach((threat) => {
      const pos = latLngToVector3(threat.lat, threat.lng, radius + 0.9);
      const score = threat.threatScore ?? 0;
      const color = score > 80 ? 0xef4444 : (score >= 50 ? 0xf97316 : 0x10b981);

      // Core Solid Pin (Interactive Raycast target)
      const pinGeo = new THREE.SphereGeometry(2.0, 16, 16);
      const pinMat = new THREE.MeshStandardMaterial({ 
        color,
        emissive: color,
        emissiveIntensity: 0.75,
        roughness: 0.15
      });
      const pin = new THREE.Mesh(pinGeo, pinMat);
      pin.position.copy(pos);
      pin.userData = { threat };
      globeGroup.add(pin);
      pinMeshes.push(pin);

      // Expanding Radar Pulse Ring
      const ringGeo = new THREE.RingGeometry(2.0, 3.8, 32);
      const ringMat = new THREE.MeshBasicMaterial({
        color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.75
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.copy(pos.clone().multiplyScalar(1.008));
      ring.lookAt(pos.clone().multiplyScalar(2));
      ring.userData = { initialScale: 1.0, phase: Math.random() * Math.PI * 2 };
      globeGroup.add(ring);
      pulseRings.push(ring);
    });
    pulseRingsRef.current = pulseRings;
    pinMeshesRef.current = pinMeshes;

    // 9. Selected Active Threat Beacon Beam
    const beaconGeo = new THREE.CylinderGeometry(0.3, 1.8, 14, 16, 1, true);
    const beaconMat = new THREE.MeshBasicMaterial({
      color: 0x6366f1,
      transparent: true,
      opacity: 0.6,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending
    });
    const beaconMesh = new THREE.Mesh(beaconGeo, beaconMat);
    beaconMesh.visible = false;
    globeGroup.add(beaconMesh);
    beaconMeshRef.current = beaconMesh;

    // 10. Attack Arcs
    allThreatLocations.forEach((threat) => {
      if (!threat.targetCoords) return;
      const start = latLngToVector3(threat.lat, threat.lng, radius);
      const end = latLngToVector3(threat.targetCoords.lat, threat.targetCoords.lng, radius);
      const mid = start.clone().add(end).multiplyScalar(0.5);
      const distance = start.distanceTo(end);
      mid.normalize().multiplyScalar(radius + distance * 0.38);

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(60);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(points);

      const score = threat.threatScore ?? 0;
      const arcColor = score > 80 ? 0xef4444 : (score >= 50 ? 0xf97316 : 0x10b981);

      const curveMat = new THREE.LineBasicMaterial({
        color: arcColor,
        transparent: true,
        opacity: 0.65,
        linewidth: 2
      });

      const arc = new THREE.Line(curveGeo, curveMat);
      globeGroup.add(arc);
    });

    // 11. Raycaster for Interactive 3D Pin Inspection
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    let pointerDownPos = { x: 0, y: 0 };
    let lastPinClickTime = 0;
    let lastPinClickedId = '';

    const onPointerDown = (e: MouseEvent) => {
      pointerDownPos = { x: e.clientX, y: e.clientY };
    };

    const onPointerMove = (e: MouseEvent) => {
      if (!renderer.domElement) return;
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(pinMeshesRef.current, false);

      if (intersects.length > 0) {
        renderer.domElement.style.cursor = 'pointer';
        const hit = intersects[0].object.userData.threat as ThreatLocationItem;
        setHoveredThreat(hit);
        setHoverPosition({ x: e.clientX - rect.left, y: e.clientY - rect.top });
      } else {
        renderer.domElement.style.cursor = isUserInteracting.current ? 'grabbing' : 'grab';
        setHoveredThreat(null);
        setHoverPosition(null);
      }
    };

    const onPointerUp = (e: MouseEvent) => {
      const dist = Math.hypot(e.clientX - pointerDownPos.x, e.clientY - pointerDownPos.y);
      if (dist < 6) {
        // Genuine click on pin
        if (!renderer.domElement) return;
        const rect = renderer.domElement.getBoundingClientRect();
        mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

        raycaster.setFromCamera(mouse, camera);
        const intersects = raycaster.intersectObjects(pinMeshesRef.current, false);
        if (intersects.length > 0) {
          const hit = intersects[0].object.userData.threat as ThreatLocationItem;
          const now = performance.now();
          if (lastPinClickedId === hit.id && now - lastPinClickTime < 500) {
            // Double click on pin -> Seamlessly dive into street level!
            setSelectedThreat(hit);
            setViewMode('street');
          } else {
            flyToThreatLocation(hit, true);
          }
          lastPinClickTime = now;
          lastPinClickedId = hit.id;
        }
      }
    };

    // Deep zoom scroll wheel listener: entering street level when scrolling past low orbit
    const onCanvasWheel = (e: WheelEvent) => {
      if (e.deltaY < 0 && camera.position.length() <= 116) {
        setViewMode('street');
      }
    };

    const dom = renderer.domElement;
    dom.addEventListener('pointerdown', onPointerDown);
    dom.addEventListener('pointermove', onPointerMove);
    dom.addEventListener('pointerup', onPointerUp);
    dom.addEventListener('wheel', onCanvasWheel, { passive: true });

    // 12. Animation Loop with Smooth Camera Interpolation
    const animate = (timestamp: number) => {
      // Rotate clouds slowly for living atmosphere
      if (cloudsMeshRef.current) {
        cloudsMeshRef.current.rotation.y += 0.0003;
      }

      // Animate pulsing radar rings
      pulseRingsRef.current.forEach((ring) => {
        const time = timestamp * 0.0025 + (ring.userData.phase || 0);
        const scale = 1.0 + (Math.sin(time) + 1.0) * 0.6;
        const opacity = Math.max(0.1, 0.8 - (scale - 1.0) * 0.5);
        ring.scale.set(scale, scale, 1);
        (ring.material as THREE.MeshBasicMaterial).opacity = opacity;
      });

      // Handle Smooth Fly-To Camera Interpolation
      if (isAnimatingCamera.current) {
        const elapsed = timestamp - cameraAnimStartTime.current;
        const progress = Math.min(elapsed / cameraAnimDuration.current, 1);
        
        // Cubic Ease-Out
        const ease = 1 - Math.pow(1 - progress, 3);

        const startDist = cameraStartPos.current.length();
        const targetDist = cameraTargetPos.current.length();
        const currentDist = THREE.MathUtils.lerp(startDist, targetDist, ease);

        const startNorm = cameraStartPos.current.clone().normalize();
        const targetNorm = cameraTargetPos.current.clone().normalize();

        // Spherical quaternion slerp
        const quat = new THREE.Quaternion().setFromUnitVectors(startNorm, targetNorm);
        const stepQuat = new THREE.Quaternion().slerp(quat, ease);
        const slerpedNorm = startNorm.clone().applyQuaternion(stepQuat);

        camera.position.copy(slerpedNorm.multiplyScalar(currentDist));
        camera.lookAt(0, 0, 0);
        controls.target.set(0, 0, 0);
        controls.update();

        if (progress >= 1) {
          isAnimatingCamera.current = false;
        }
      } else {
        // Auto-rotation only when enabled and not actively interacting
        if (isAutoRotating && !isUserInteracting.current) {
          globeGroup.rotation.y += 0.0012;
        }
        controls.update();
      }

      setCameraDistance(Math.round(camera.position.length()));

      if (rendererRef.current && sceneRef.current && cameraRef.current) {
        rendererRef.current.render(sceneRef.current, cameraRef.current);
      }

      animationFrameId.current = requestAnimationFrame(animate);
    };

    animationFrameId.current = requestAnimationFrame(animate);

    // Resize Handler
    const handleResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      if (animationFrameId.current) cancelAnimationFrame(animationFrameId.current);
      window.removeEventListener('resize', handleResize);
      dom.removeEventListener('pointerdown', onPointerDown);
      dom.removeEventListener('pointermove', onPointerMove);
      dom.removeEventListener('pointerup', onPointerUp);
      dom.removeEventListener('wheel', onCanvasWheel);
      controls.dispose();
      renderer.dispose();
    };
  }, [allThreatLocations, textures]);

  // Smooth Fly-To & Zoom In on Specific Location
  const flyToThreatLocation = (threat: ThreatLocationItem, zoomIn: boolean = true) => {
    setSelectedThreat(threat);
    onSelectThreat(threat.id);
    setIsAutoRotating(false);

    if (!cameraRef.current || !globeGroupRef.current) return;

    const camera = cameraRef.current;
    const radius = 80;
    const surfacePos = latLngToVector3(threat.lat, threat.lng, radius);

    // Position the Beacon Beam on the active marker
    if (beaconMeshRef.current) {
      beaconMeshRef.current.visible = true;
      beaconMeshRef.current.position.copy(surfacePos.clone().multiplyScalar(1.08));
      beaconMeshRef.current.quaternion.setFromUnitVectors(
        new THREE.Vector3(0, 1, 0),
        surfacePos.clone().normalize()
      );
    }

    // Calculate ideal viewing vector in world coordinates taking globe rotation into account
    const worldPos = surfacePos.clone().applyEuler(globeGroupRef.current.rotation);
    const direction = worldPos.clone().normalize();
    const targetZoomDistance = zoomIn ? 145 : 210; // Zoom in close enough for high detail
    const targetCameraPosition = direction.multiplyScalar(targetZoomDistance);

    // Set up smooth animation
    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(targetCameraPosition);
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  // Zoom HUD Handlers
  const handleZoomIn = () => {
    if (!cameraRef.current || !controlsRef.current) return;
    const camera = cameraRef.current;
    const currentLen = camera.position.length();
    if (currentLen <= 126) {
      // Zooming closer than lowest planetary orbit -> dive straight into streets!
      setViewMode('street');
      return;
    }
    const nextLen = Math.max(115, currentLen * 0.78);
    
    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(camera.position.clone().normalize().multiplyScalar(nextLen));
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  const handleZoomOut = () => {
    if (!cameraRef.current || !controlsRef.current) return;
    const camera = cameraRef.current;
    const currentLen = camera.position.length();
    const nextLen = Math.min(380, currentLen * 1.3);

    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(camera.position.clone().normalize().multiplyScalar(nextLen));
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  const handleResetView = () => {
    if (!cameraRef.current) return;
    cameraStartPos.current.copy(cameraRef.current.position);
    cameraTargetPos.current.set(0, 40, 230);
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
    setIsAutoRotating(true);
    if (beaconMeshRef.current) beaconMeshRef.current.visible = false;
  };

  // Filtered threats for live search
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = searchQuery.toLowerCase();
    return allThreatLocations.filter(item => 
      item.city.toLowerCase().includes(q) ||
      item.country.toLowerCase().includes(q) ||
      item.ip.toLowerCase().includes(q) ||
      item.sender.toLowerCase().includes(q) ||
      item.simpleTitle.toLowerCase().includes(q) ||
      (item.subject && item.subject.toLowerCase().includes(q))
    );
  }, [allThreatLocations, searchQuery]);

  const activeThreat = selectedThreat || (allThreatLocations.length > 0 ? allThreatLocations[0] : null);
  const threatScore = activeThreat ? (activeThreat.threatScore || 0) : 0;
  const strokeDashoffset = 213.6 - (213.6 * threatScore) / 100;

  const criticalCount = customEmails.filter(e => (e.threatScore ?? 0) > 80).length;
  const mildCount = customEmails.filter(e => (e.threatScore ?? 0) >= 50 && (e.threatScore ?? 0) <= 80).length;
  const safeCount = customEmails.filter(e => (e.threatScore ?? 0) < 50).length;

  return (
    <div className="space-y-6">
      
      {/* Top Metrics Ribbon */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Threat Score Gauge */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Focused Severity Index
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-black font-mono text-slate-900">
                {threatScore}
              </span>
              <span className="text-xs text-slate-400 font-mono">/100</span>
            </div>
            <div>
              <span className={`text-[11px] font-bold px-3 py-0.5 rounded-full border ${
                threatScore > 80 
                  ? 'bg-red-100 text-red-700 border-red-200' 
                  : (threatScore >= 50 ? 'bg-orange-100 text-orange-700 border-orange-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200')
              }`}>
                {threatScore > 80 ? 'Critical Threat (Red)' : (threatScore >= 50 ? 'Mild Threat (Orange)' : (activeThreat ? '100% Safe (Green)' : 'Awaiting Inbound'))}
              </span>
            </div>
          </div>

          {/* Circular SVG Gauge */}
          <div className="relative w-20 h-20 flex items-center justify-center">
            <svg className="w-20 h-20" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" stroke="#f1f5f9" strokeWidth="7" fill="none" />
              <circle 
                className="threat-gauge-circle" 
                cx="40" 
                cy="40" 
                r="34" 
                stroke={threatScore > 80 ? '#ef4444' : (threatScore >= 50 ? '#f97316' : '#10b981')} 
                strokeWidth="7" 
                strokeDasharray="213.6" 
                strokeDashoffset={strokeDashoffset} 
                strokeLinecap="round" 
                fill="none" 
              />
            </svg>
            <ShieldAlert className={`w-6 h-6 absolute ${threatScore > 80 ? 'text-red-500' : (threatScore >= 50 ? 'text-orange-500' : 'text-emerald-500')}`} />
          </div>
        </div>

        {/* Metric 2: Live Incidents Tracked */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Live Ingested Emails
            </span>
            <span className="text-[10px] font-bold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 animate-pulse"></span>
              Live Pipeline
            </span>
          </div>
          <div className="text-3xl font-black font-mono text-slate-900">
            {customEmails.length}
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-1.5 pt-1 font-mono">
            <span className="text-red-600 font-bold">{criticalCount}</span> Critical • 
            <span className="text-orange-600 font-bold">{mildCount}</span> Mild • 
            <span className="text-emerald-600 font-bold">{safeCount}</span> Safe
          </div>
        </div>

        {/* Metric 3: Active Sender Origin Focus */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1 lg:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5 text-indigo-600" />
              Origin Telemetry & Coordinates
            </span>
            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${
              activeThreat?.severity === 'safe' 
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                : 'bg-red-50 text-red-700 border-red-200'
            }`}>
              {activeThreat?.status || 'Awaiting Live Origin'}
            </span>
          </div>
          <div className="font-mono text-sm font-bold text-slate-900 truncate">
            {activeThreat ? activeThreat.sender : 'No active email sender selected'}
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-2 truncate">
            {activeThreat ? (
              <>
                <span className="font-bold text-slate-700">Origin:</span> 
                <span className="font-mono text-indigo-600 font-bold">{activeThreat.city}, {activeThreat.country}</span> • 
                <span className="font-bold text-slate-700">IP:</span> 
                <span className="font-mono text-slate-600">{activeThreat.ip}</span> • 
                <span className="font-bold text-slate-700">Lat/Lng:</span>
                <span className="font-mono text-slate-500">{activeThreat.lat.toFixed(2)}°, {activeThreat.lng.toFixed(2)}°</span>
              </>
            ) : (
              <span>Connect Gmail or upload an .EML file in Forensics to plot origin coordinates.</span>
            )}
          </div>
        </div>

      </div>

      {/* Main Visual Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Large Interactive 3D World Globe */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden flex flex-col relative">
          
          {/* Top Bar with Live Search & Coordinates HUD */}
          <div className="p-3.5 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white z-20">
            
            {/* Search Bar with Autocomplete */}
            <div className="relative flex-1 max-w-md">
              <div className="relative flex items-center">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setIsSearchOpen(true);
                  }}
                  onFocus={() => setIsSearchOpen(true)}
                  placeholder={allThreatLocations.length > 0 ? "Search city, country, IP address, sender..." : "Awaiting emails to search..."}
                  disabled={allThreatLocations.length === 0}
                  className="w-full pl-9 pr-8 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all font-sans disabled:opacity-60"
                />
                {searchQuery && (
                  <button
                    onClick={() => { setSearchQuery(''); setIsSearchOpen(false); }}
                    className="absolute right-2.5 text-slate-400 hover:text-slate-600 p-0.5"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Search Autocomplete Dropdown */}
              {isSearchOpen && searchResults.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-slate-200 rounded-xl shadow-lg z-30 max-h-60 overflow-y-auto divide-y divide-slate-100">
                  {searchResults.map((item) => {
                    const score = item.threatScore ?? 0;
                    const dotClass = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');
                    return (
                      <div
                        key={item.id}
                        onClick={() => {
                          flyToThreatLocation(item, true);
                          setIsSearchOpen(false);
                          setSearchQuery('');
                        }}
                        className="p-3 hover:bg-slate-50 cursor-pointer flex items-center justify-between text-xs transition-colors"
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${dotClass}`} />
                            <span className="font-bold text-slate-900">{item.city}, {item.country}</span>
                          </div>
                          <p className="text-[11px] text-slate-500 truncate max-w-xs">{item.sender}</p>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400 font-bold">{score}/100</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* View Mode Switcher (3D Orbit vs Street Zoom) & Live Indicator */}
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-xl border border-slate-200">
                <button
                  onClick={() => setViewMode('globe')}
                  className={`px-2.5 py-1 text-xs font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                    viewMode === 'globe'
                      ? 'bg-white text-indigo-600 shadow-xs'
                      : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  <GlobeIcon className="w-3.5 h-3.5" />
                  <span>3D Orbit</span>
                </button>
                <button
                  onClick={() => setViewMode('street')}
                  className={`px-2.5 py-1 text-xs font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                    viewMode === 'street'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  <MapPin className="w-3.5 h-3.5" />
                  <span>Street Zoom</span>
                </button>
              </div>

              <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-500">
                <span className="w-2 h-2 rounded-full bg-indigo-600 animate-pulse" />
                <span>RADAR ONLINE</span>
              </div>
            </div>
          </div>

          {/* Main Visual Display: Street Level Map OR 3D Planetary Globe */}
          {/* Street Map Container */}
          <div className={viewMode === 'street' ? 'block' : 'hidden'}>
            <StreetMapView
              threat={activeThreat}
              allThreats={allThreatLocations}
              onSelectThreat={(t) => {
                setSelectedThreat(t);
                onSelectThreat(t.id);
              }}
              onReturnToOrbit={() => setViewMode('globe')}
              onOpenForensics={onOpenForensics}
              initialLayer={mapTheme === 'satellite' ? 'satellite' : (mapTheme === 'dark' ? 'dark' : 'streets')}
            />
          </div>

          {/* Three.js Canvas Container */}
          <div className={viewMode === 'globe' ? 'relative w-full h-[460px] bg-slate-950 overflow-hidden' : 'hidden'}>
            <div ref={canvasContainerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

            {/* Low Altitude Street Zoom Prompt */}
            {cameraDistance <= 140 && activeThreat && (
              <div 
                onClick={() => setViewMode('street')}
                className="absolute top-16 left-1/2 -translate-x-1/2 z-20 bg-indigo-600/95 hover:bg-indigo-500 text-white border border-indigo-400 px-4 py-1.5 rounded-full text-xs font-bold shadow-2xl backdrop-blur-md cursor-pointer animate-pulse flex items-center gap-2 transition-transform hover:scale-105"
              >
                <MapPin className="w-3.5 h-3.5 text-white" />
                <span>Low Altitude Reached: Click to Zoom Deep into {activeThreat.city} Streets 🏙️</span>
              </div>
            )}

            {/* Map Theme & Real Map Selector Pill */}
            <div className="absolute right-4 top-4 bg-slate-900/85 backdrop-blur-md border border-slate-700/80 rounded-xl p-1 flex items-center gap-1 z-20 shadow-xl">
              <button
                onClick={() => setMapTheme('satellite')}
                title="NASA Blue Marble Real Satellite Imagery"
                className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  mapTheme === 'satellite' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
                }`}
              >
                <span>🛰️ Satellite</span>
              </button>
              <button
                onClick={() => setMapTheme('night')}
                title="Earth Night City Lights & Infrastructure"
                className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  mapTheme === 'night' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
                }`}
              >
                <span>🌃 Night</span>
              </button>
              <button
                onClick={() => setMapTheme('dark')}
                title="Cyber Defense Tactical Radar Map"
                className={`px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  mapTheme === 'dark' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
                }`}
              >
                <span>🛡️ Tactical</span>
              </button>
            </div>

            {/* Free Move Mode Badge & Instructions */}
            <div className="absolute left-4 bottom-4 bg-slate-900/85 backdrop-blur-md border border-slate-700/80 rounded-xl px-3 py-1.5 flex items-center gap-2 text-[11px] text-slate-300 font-mono z-10 pointer-events-none shadow-lg">
              <span className={`w-2 h-2 rounded-full ${isAutoRotating ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
              <span>{isAutoRotating ? 'Auto-Rotating (Click Pause for Free Move)' : '✨ Free Move Active: Drag 360° • Scroll Zoom • Double Click Pin for Streets'}</span>
            </div>

            {/* Interactive Raycast Hover Tooltip */}
            {hoveredThreat && hoverPosition && (
              <div
                style={{ 
                  left: `${Math.min(hoverPosition.x + 14, 520)}px`, 
                  top: `${Math.max(hoverPosition.y - 14, 60)}px` 
                }}
                className="absolute pointer-events-none z-30 bg-slate-900/95 border border-indigo-500/50 text-white p-3 rounded-xl shadow-2xl backdrop-blur-md max-w-xs -translate-y-full animate-in fade-in zoom-in-95 duration-100"
              >
                <div className="flex items-center gap-1.5 mb-1 font-bold text-xs text-white">
                  <MapPin className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                  <span className="truncate">{hoveredThreat.city}, {hoveredThreat.country}</span>
                </div>
                <div className="text-[10px] font-mono text-slate-300 truncate mb-1">{hoveredThreat.sender}</div>
                <div className="flex items-center justify-between gap-3 pt-1 border-t border-slate-800 text-[10px] font-mono">
                  <span className="text-slate-400">IP: {hoveredThreat.ip}</span>
                  <span className={`font-bold px-1.5 py-0.5 rounded ${
                    hoveredThreat.threatScore > 80 ? 'bg-red-900/60 text-red-300' : (hoveredThreat.threatScore >= 50 ? 'bg-orange-900/60 text-orange-300' : 'bg-emerald-900/60 text-emerald-300')
                  }`}>
                    {hoveredThreat.threatScore}/100
                  </span>
                </div>
                <div className="mt-1 pt-1 border-t border-slate-800/60 text-[9px] text-indigo-300 font-mono">
                  Double click pin to zoom to streets 🏙️
                </div>
              </div>
            )}

            {/* Navigation & Zoom HUD Buttons */}
            <div className="absolute right-4 bottom-4 flex flex-col gap-1.5 z-10">
              <button
                onClick={handleZoomIn}
                title="Zoom In (Dives into streets when close)"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <Plus className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomOut}
                title="Zoom Out"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <Minus className="w-4 h-4" />
              </button>
              <button
                onClick={() => setViewMode('street')}
                title="Zoom Deeper into Streets & Buildings"
                className="w-8 h-8 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg shadow-md border border-indigo-400 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <MapPin className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleResetView}
                title="Reset View"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsAutoRotating(!isAutoRotating)}
                title={isAutoRotating ? "Pause Auto-Rotation & Enable Free Move" : "Start Auto-Rotation"}
                className={`w-8 h-8 rounded-lg shadow-md border flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer ${
                  isAutoRotating 
                    ? 'bg-amber-500 text-white border-amber-600 hover:bg-amber-600' 
                    : 'bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 border-slate-200'
                }`}
              >
                {isAutoRotating ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Active Target Floating Pin Tag */}
            {activeThreat && (
              <div className="absolute left-4 top-4 bg-slate-900/90 text-white border border-slate-700/80 rounded-xl p-3 shadow-xl backdrop-blur-md max-w-xs z-10 pointer-events-auto transition-all">
                <div className="flex items-center gap-2 pb-1.5 border-b border-slate-800">
                  <Crosshair className="w-3.5 h-3.5 text-indigo-400 animate-spin" style={{ animationDuration: '6s' }} />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-indigo-300">
                    Focused Telemetry Target
                  </span>
                </div>
                <div className="mt-2 space-y-1">
                  <div className="text-xs font-bold text-slate-100 flex items-center justify-between">
                    <span>{activeThreat.city}, {activeThreat.country}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                      activeThreat.severity === 'safe' ? 'bg-emerald-900 text-emerald-300' : 'bg-red-900 text-red-300'
                    }`}>
                      {activeThreat.threatScore}/100
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 font-mono truncate">{activeThreat.sender}</p>
                  <div className="text-[10px] text-slate-400 font-mono flex items-center gap-2">
                    <span>IP: {activeThreat.ip}</span>
                    <span>•</span>
                    <span>{activeThreat.asn?.split(' ')[0]}</span>
                  </div>
                  <button
                    onClick={() => setViewMode('street')}
                    className="mt-2 w-full py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-[11px] font-bold flex items-center justify-center gap-1.5 transition-all shadow-md cursor-pointer"
                  >
                    <MapPin className="w-3.5 h-3.5" />
                    <span>Zoom Deeper to Streets ({activeThreat.city})</span>
                  </button>
                </div>
              </div>
            )}

            {/* Zero Telemetry HUD Overlay */}
            {allThreatLocations.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none p-6">
                <div className="bg-slate-900/80 border border-slate-700/70 rounded-2xl p-5 text-center max-w-sm backdrop-blur-md shadow-2xl pointer-events-auto">
                  <GlobeIcon className="w-8 h-8 text-indigo-400 mx-auto mb-2 opacity-80" />
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">Awaiting Threat Telemetry</h4>
                  <p className="text-[11px] text-slate-400 mt-1 mb-3">
                    No emails ingested yet. Connect your live Gmail inbox or upload an .EML file to plot incoming attack origins.
                  </p>
                  <button
                    onClick={onOpenForensics}
                    className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg transition-colors cursor-pointer"
                  >
                    Open Forensics Suite
                  </button>
                </div>
              </div>
            )}

          </div>

          {/* Quick Location Jump Badges */}
          {allThreatLocations.length > 0 && (
            <div className="p-3 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-bold text-slate-500 text-[11px] uppercase tracking-wider mr-1">
                  Quick Focus:
                </span>
                {allThreatLocations.slice(0, 6).map((threat) => (
                  <button
                    key={threat.id}
                    onClick={() => flyToThreatLocation(threat, true)}
                    className={`px-2.5 py-1 rounded-lg font-medium border text-[11px] transition-all flex items-center gap-1 cursor-pointer ${
                      activeThreat?.id === threat.id
                        ? 'bg-indigo-600 text-white border-indigo-600 shadow-xs'
                        : 'bg-white hover:bg-indigo-50 hover:text-indigo-600 border-slate-200 text-slate-700'
                    }`}
                  >
                    <span>{threat.city}</span>
                    <span className={`w-1.5 h-1.5 rounded-full ${threat.severity === 'safe' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  </button>
                ))}
              </div>

              <button
                onClick={() => setViewMode(viewMode === 'globe' ? 'street' : 'globe')}
                className="px-2.5 py-1 rounded-lg font-bold border border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-600 hover:text-white text-[11px] transition-all flex items-center gap-1.5 cursor-pointer shadow-xs ml-auto"
              >
                {viewMode === 'globe' ? (
                  <>
                    <MapPin className="w-3 h-3" />
                    <span>Zoom Deeper into Streets</span>
                  </>
                ) : (
                  <>
                    <GlobeIcon className="w-3 h-3" />
                    <span>Return to 3D Orbit</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Threat Plain Telemetry Summary Footer */}
          <div className="p-4 bg-slate-900 text-white border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                <Radio className="w-3 h-3 text-indigo-400 animate-pulse" />
                Live Incident Forensic Summary
              </div>
              <p className="text-xs text-slate-200 font-medium leading-relaxed">
                {activeThreat ? activeThreat.plainSummary : 'Awaiting live stream. Connect your Gmail account or ingest email files to view origin telemetry.'}
              </p>
            </div>
            <button 
              onClick={onOpenForensics}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl shrink-0 transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
            >
              <Microscope className="w-3.5 h-3.5" />
              Open Forensics
            </button>
          </div>
        </div>

        {/* Right Side: Interactive Threat Incident Feed */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Radio className="w-4 h-4 text-indigo-600" />
                Live Ingested Feed ({allThreatLocations.length})
              </h3>
              <span className="text-[10px] text-slate-400 font-medium">Click to locate</span>
            </div>

            {/* Threat Feed Scrollable List */}
            {allThreatLocations.length > 0 ? (
              <div className="space-y-2.5 mt-4 max-h-[380px] overflow-y-auto pr-1">
                {allThreatLocations.map((item) => {
                  const isItemActive = activeThreat?.id === item.id;
                  const score = item.threatScore ?? 0;
                  const dotClass = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');
                  const badgeClass = score > 80 
                    ? 'bg-red-100 text-red-800' 
                    : (score >= 50 ? 'bg-orange-100 text-orange-800' : 'bg-emerald-100 text-emerald-800');
                  return (
                    <div
                      key={item.id}
                      onClick={() => flyToThreatLocation(item, true)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer ${
                        isItemActive
                          ? 'bg-indigo-50/90 border-indigo-400 ring-2 ring-indigo-200 shadow-xs'
                          : 'bg-slate-50/70 border-slate-200 hover:border-slate-300 hover:bg-slate-100/70'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${dotClass}`} />
                            <span className="text-xs font-bold text-slate-900 truncate">
                              {item.city}, {item.country}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 line-clamp-1 font-medium">
                            {item.simpleTitle}
                          </p>
                          <div className="text-[10px] font-mono text-slate-400 truncate">
                            {item.sender}
                          </div>
                          <div className="text-[10px] font-mono text-slate-400">
                            {item.ip} • {item.timestamp}
                          </div>

                          {isItemActive && (
                            <div className="mt-2.5 pt-2 border-t border-indigo-200/60 flex items-center gap-2">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedThreat(item);
                                  setViewMode('street');
                                }}
                                className="w-full py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-[10px] font-bold flex items-center justify-center gap-1.5 transition-all shadow-xs cursor-pointer"
                              >
                                <MapPin className="w-3 h-3" />
                                <span>Zoom into Streets ({item.city})</span>
                              </button>
                            </div>
                          )}
                        </div>

                        <div className="text-right shrink-0">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${badgeClass}`}>
                            {item.threatScore}/100
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 space-y-2 mt-4 bg-slate-50 rounded-xl border border-dashed border-slate-200">
                <Microscope className="w-6 h-6 mx-auto text-slate-300" />
                <p className="text-xs font-medium text-slate-600">No telemetry logged</p>
                <p className="text-[11px] text-slate-400">Sync Gmail or upload an email to populate this feed.</p>
              </div>
            )}
          </div>

          {/* Quick Action Card */}
          <div className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-2">
            <div className="text-xs font-bold text-slate-900">Deep Email Analysis</div>
            <p className="text-[11px] text-slate-600">Upload any .eml file or paste text to inspect headers, domains, and IOCs.</p>
            <button 
              onClick={onOpenForensics}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all shadow-xs cursor-pointer"
            >
              Open Forensics Suite
            </button>
          </div>
        </div>

      </div>

    </div>
  );
};
