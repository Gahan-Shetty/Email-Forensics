/**
 * Authentic ThreeUI Kage-Inspired 3D Kyoto Temple Night Scene
 * Features 3D Torii / Pavilion wireframe architecture, warm vermilion & amber lantern illumination,
 * rising ember particles, mist fog, and scroll-linked camera interpolation.
 */

(function (window) {
  "use strict";

  var scene, camera, renderer, templeGroup, embersSystem;
  var targetCameraY = 0;
  var targetCameraZ = 6;
  var targetRotationY = 0;
  var targetRotationX = 0;
  var mouseX = 0, mouseY = 0;
  var windowHalfX = window.innerWidth / 2;
  var windowHalfY = window.innerHeight / 2;

  function initThreeScene() {
    var canvas = document.getElementById("three-canvas");
    if (!canvas || typeof THREE === "undefined") {
      console.warn("Three.js not loaded or canvas missing");
      return;
    }

    // 1. Scene with Kage Temple Fog
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05070a, 0.09);

    camera = new THREE.PerspectiveCamera(48, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.z = 6;
    camera.position.y = 0;

    // 2. Renderer
    renderer = new THREE.WebGLRenderer({
      canvas: canvas,
      alpha: true,
      antialias: true,
      powerPreference: "high-performance"
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // 3. Kage 3D Architectural / Temple Wireframe Nodes
    templeGroup = new THREE.Group();
    scene.add(templeGroup);

    // Torii Gate Pillar & Crossbeam Structure
    var beamMat = new THREE.MeshBasicMaterial({
      color: 0xf47b5c,
      wireframe: true,
      transparent: true,
      opacity: 0.35
    });

    var amberMat = new THREE.MeshBasicMaterial({
      color: 0xf9c74f,
      wireframe: true,
      transparent: true,
      opacity: 0.25
    });

    // Outer Geodetic Forensic Cage (Sanmon)
    var domeGeo = new THREE.IcosahedronGeometry(2.2, 3);
    var domeMesh = new THREE.Mesh(domeGeo, beamMat);
    templeGroup.add(domeMesh);

    // Inner Amber Pavilion Ring
    var ringGeo = new THREE.TorusGeometry(1.8, 0.02, 16, 100);
    var ringMesh = new THREE.Mesh(ringGeo, amberMat);
    ringMesh.rotation.x = Math.PI / 2.2;
    templeGroup.add(ringMesh);

    var ringGeo2 = new THREE.TorusGeometry(2.4, 0.015, 16, 100);
    var ringMesh2 = new THREE.Mesh(ringGeo2, beamMat);
    ringMesh2.rotation.x = Math.PI / 1.8;
    templeGroup.add(ringMesh2);

    // Geodesic Data Nodes (Lantern points)
    var nodeGeo = new THREE.BufferGeometry();
    var nodeCount = 450;
    var nodePos = new Float32Array(nodeCount * 3);
    var nodeCols = new Float32Array(nodeCount * 3);

    for (var i = 0; i < nodeCount; i++) {
      var u = Math.random();
      var v = Math.random();
      var theta = u * 2.0 * Math.PI;
      var phi = Math.acos(2.0 * v - 1.0);
      var r = 2.22 + (Math.random() * 0.1);

      var sinPhi = Math.sin(phi);
      nodePos[i * 3] = r * sinPhi * Math.cos(theta);
      nodePos[i * 3 + 1] = r * sinPhi * Math.sin(theta);
      nodePos[i * 3 + 2] = r * Math.cos(phi);

      var isAmber = Math.random() > 0.4;
      nodeCols[i * 3] = isAmber ? 0.97 : 0.95;     // R
      nodeCols[i * 3 + 1] = isAmber ? 0.78 : 0.48; // G
      nodeCols[i * 3 + 2] = isAmber ? 0.31 : 0.36; // B
    }

    nodeGeo.setAttribute('position', new THREE.BufferAttribute(nodePos, 3));
    nodeGeo.setAttribute('color', new THREE.BufferAttribute(nodeCols, 3));

    var nodeMat = new THREE.PointsMaterial({
      size: 0.05,
      vertexColors: true,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending
    });
    var nodeMesh = new THREE.Points(nodeGeo, nodeMat);
    templeGroup.add(nodeMesh);

    // 4. Rising Ember Particles (Kyoto Lantern Fireflies)
    var emberGeo = new THREE.BufferGeometry();
    var emberCount = 350;
    var emberPositions = new Float32Array(emberCount * 3);

    for (var e = 0; e < emberCount; e++) {
      emberPositions[e * 3] = (Math.random() - 0.5) * 16;
      emberPositions[e * 3 + 1] = (Math.random() - 0.5) * 16;
      emberPositions[e * 3 + 2] = (Math.random() - 0.5) * 12;
    }

    emberGeo.setAttribute('position', new THREE.BufferAttribute(emberPositions, 3));
    var emberMat = new THREE.PointsMaterial({
      size: 0.035,
      color: 0xf9c74f,
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending
    });
    embersSystem = new THREE.Points(emberGeo, emberMat);
    scene.add(embersSystem);

    // 5. Lighting
    var ambient = new THREE.AmbientLight(0xfff5ea, 0.6);
    scene.add(ambient);

    var lanternLight = new THREE.PointLight(0xf47b5c, 2.5, 18);
    lanternLight.position.set(3, 2, 4);
    scene.add(lanternLight);

    // 6. Listeners
    window.addEventListener("resize", onResize);
    document.addEventListener("mousemove", onMouseMove);
    window.addEventListener("scroll", onScroll);

    onScroll();
    animate();
  }

  function onResize() {
    windowHalfX = window.innerWidth / 2;
    windowHalfY = window.innerHeight / 2;
    if (camera && renderer) {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    }
  }

  function onMouseMove(e) {
    mouseX = (e.clientX - windowHalfX) * 0.0005;
    mouseY = (e.clientY - windowHalfY) * 0.0005;
  }

  function onScroll() {
    var scrollY = window.scrollY || window.pageYOffset;
    var docHeight = document.documentElement.scrollHeight - window.innerHeight;
    var progress = docHeight > 0 ? (scrollY / docHeight) : 0;

    if (progress < 0.2) {
      targetCameraY = 0;
      targetCameraZ = 5.8;
      if (templeGroup) {
        templeGroup.position.x = 0.8;
        templeGroup.position.y = 0;
      }
    } else if (progress < 0.5) {
      targetCameraY = -0.4;
      targetCameraZ = 7.2;
      if (templeGroup) {
        templeGroup.position.x = 2.0;
        templeGroup.position.y = 0.4;
      }
    } else if (progress < 0.75) {
      targetCameraY = 0.4;
      targetCameraZ = 6.6;
      if (templeGroup) {
        templeGroup.position.x = -2.0;
        templeGroup.position.y = -0.3;
      }
    } else {
      targetCameraY = 0;
      targetCameraZ = 8.0;
      if (templeGroup) {
        templeGroup.position.x = 0;
        templeGroup.position.y = 0;
      }
    }

    targetRotationY = progress * Math.PI * 2;
  }

  function animate() {
    requestAnimationFrame(animate);

    if (templeGroup) {
      templeGroup.rotation.y += 0.0012;
      templeGroup.rotation.y += (targetRotationY + mouseX - templeGroup.rotation.y) * 0.05;
      templeGroup.rotation.x += (mouseY - templeGroup.rotation.x) * 0.05;
    }

    if (embersSystem) {
      var positions = embersSystem.geometry.attributes.position.array;
      for (var i = 1; i < positions.length; i += 3) {
        positions[i] += 0.004; // Slowly rising embers
        if (positions[i] > 8) positions[i] = -8;
      }
      embersSystem.geometry.attributes.position.needsUpdate = true;
      embersSystem.rotation.y -= 0.0003;
    }

    if (camera) {
      camera.position.y += (targetCameraY - camera.position.y) * 0.04;
      camera.position.z += (targetCameraZ - camera.position.z) * 0.04;
      camera.lookAt(0, 0, 0);
    }

    if (renderer && scene && camera) {
      renderer.render(scene, camera);
    }
  }

  window.initThreeScene = initThreeScene;

})(window);
