/**
 * Kyoto Night Bubble Cursor Engine — Email Forensic Analyzer
 * Creates an ethereal, interactive bubble particle field around the cursor.
 * Features:
 * - Fluid floating bubbles with upward buoyancy and sinusoidal drift
 * - Translucent iridescent body with inner crescent specular reflection and rim glow
 * - Dynamic color palettes matching Kyoto Night (Vermilion, Amber, Emerald, Water Cyan)
 * - Ambient bubble breathing when cursor is stationary
 * - Click-burst pop splitting into mini water droplet sparks
 * - High-DPI support, zero layout thrashing, 60-120fps optimized
 */

(function (window, document) {
  "use strict";

  // Check for reduced motion preference
  var prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) return;

  var canvas, ctx;
  var width = 0, height = 0, dpr = 1;
  var particles = [];
  var sparkParticles = [];
  var mouse = { x: -1000, y: -1000, lastX: -1000, lastY: -1000, speed: 0, isMoving: false };
  var lastMoveTime = Date.now();
  var ambientTimer = 0;
  var maxParticles = 65;

  // Kyoto-inspired translucent color palettes with iridescent water tint
  var bubbleColors = [
    { r: 244, g: 123, b: 92,  name: "vermilion" }, // Kyoto Vermilion
    { r: 249, g: 199, b: 79,  name: "amber" },     // Lantern Amber
    { r: 88,  g: 198, b: 138, name: "emerald" },   // Temple Moss Emerald
    { r: 130, g: 215, b: 255, name: "water-cyan" },// Kyoto Mist Water
    { r: 180, g: 230, b: 255, name: "crystal" }    // Pure Shimmer
  ];

  function Bubble(x, y, radius, color, vx, vy) {
    this.x = x + (Math.random() - 0.5) * 16;
    this.y = y + (Math.random() - 0.5) * 16;
    this.initialRadius = radius || (Math.random() * 12 + 6);
    this.radius = this.initialRadius;
    this.maxRadius = this.initialRadius * (1.25 + Math.random() * 0.4);
    this.color = color || bubbleColors[Math.floor(Math.random() * bubbleColors.length)];
    
    // Physics velocities: upward buoyancy with gentle random initial impulses
    this.vx = (vx !== undefined) ? vx : (Math.random() - 0.5) * 1.8;
    this.vy = (vy !== undefined) ? vy : -(Math.random() * 1.6 + 0.8);
    
    // Wobble parameters
    this.wobbleSpeed = Math.random() * 0.06 + 0.03;
    this.wobbleAmp = Math.random() * 1.2 + 0.6;
    this.wobblePhase = Math.random() * Math.PI * 2;
    
    // Lifespan and alpha
    this.life = 0;
    this.maxLife = Math.random() * 50 + 55; // ~1 to 2 seconds
    this.alpha = 0;
    this.targetAlpha = Math.random() * 0.45 + 0.35;
    this.isDead = false;
  }

  Bubble.prototype.update = function () {
    this.life++;
    
    // Fade in quickly, then gently fade out towards end of life
    if (this.life < 10) {
      this.alpha += (this.targetAlpha - this.alpha) * 0.25;
    } else if (this.life > this.maxLife - 25) {
      this.alpha *= 0.92;
    }

    // Upward buoyancy & air resistance
    this.vy -= 0.045; // gentle upward lift
    this.vx *= 0.97;
    this.vy *= 0.98;

    // Sinusoidal floating drift
    var wobble = Math.sin(this.life * this.wobbleSpeed + this.wobblePhase) * this.wobbleAmp;
    this.x += this.vx + wobble;
    this.y += this.vy;

    // Slow growth like natural soap/water bubble tension
    if (this.radius < this.maxRadius) {
      this.radius += 0.04;
    }

    if (this.life >= this.maxLife || this.alpha < 0.01) {
      this.isDead = true;
    }
  };

  Bubble.prototype.draw = function (ctx) {
    if (this.alpha <= 0) return;

    var r = this.radius;
    var c = this.color;
    ctx.save();
    ctx.translate(this.x, this.y);

    // 1. Outer Translucent Liquid Body
    var bodyGrad = ctx.createRadialGradient(-r * 0.2, -r * 0.3, r * 0.1, 0, 0, r);
    bodyGrad.addColorStop(0, "rgba(255, 255, 255, " + (this.alpha * 0.2) + ")");
    bodyGrad.addColorStop(0.5, "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + (this.alpha * 0.08) + ")");
    bodyGrad.addColorStop(0.85, "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + (this.alpha * 0.35) + ")");
    bodyGrad.addColorStop(1, "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + (this.alpha * 0.7) + ")");

    ctx.beginPath();
    ctx.arc(0, 0, r, 0, Math.PI * 2);
    ctx.fillStyle = bodyGrad;
    ctx.fill();

    // 2. Iridescent Rim / Membrane Glow
    ctx.beginPath();
    ctx.arc(0, 0, r, 0, Math.PI * 2);
    ctx.lineWidth = Math.max(0.8, r * 0.08);
    ctx.strokeStyle = "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + (this.alpha * 0.85) + ")";
    ctx.stroke();

    // 3. Primary Specular Highlight (Curved Crescent Arc at top-left)
    ctx.beginPath();
    ctx.ellipse(-r * 0.35, -r * 0.35, r * 0.32, r * 0.16, -Math.PI / 4, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(255, 255, 255, " + (this.alpha * 0.9) + ")";
    ctx.fill();

    // 4. Secondary Soft Internal Reflection (Bottom-Right)
    ctx.beginPath();
    ctx.arc(r * 0.25, r * 0.25, r * 0.18, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(255, 255, 255, " + (this.alpha * 0.3) + ")";
    ctx.fill();

    ctx.restore();
  };

  // Mini Droplet Spark for Bubble Pop / Click Burst
  function Spark(x, y, color) {
    this.x = x;
    this.y = y;
    var angle = Math.random() * Math.PI * 2;
    var speed = Math.random() * 3.5 + 1.2;
    this.vx = Math.cos(angle) * speed;
    this.vy = Math.sin(angle) * speed - 0.5;
    this.radius = Math.random() * 2 + 1;
    this.color = color || bubbleColors[Math.floor(Math.random() * bubbleColors.length)];
    this.alpha = 0.9;
    this.life = 0;
    this.maxLife = Math.random() * 20 + 15;
    this.isDead = false;
  }

  Spark.prototype.update = function () {
    this.life++;
    this.x += this.vx;
    this.y += this.vy;
    this.vx *= 0.94;
    this.vy += 0.08; // gravity for droplet droplets
    this.alpha = Math.max(0, 0.9 * (1 - this.life / this.maxLife));
    if (this.life >= this.maxLife) this.isDead = true;
  };

  Spark.prototype.draw = function (ctx) {
    if (this.alpha <= 0) return;
    var c = this.color;
    ctx.save();
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + this.alpha + ")";
    ctx.shadowColor = "rgba(" + c.r + ", " + c.g + ", " + c.b + ", " + (this.alpha * 0.8) + ")";
    ctx.shadowBlur = 4;
    ctx.fill();
    ctx.restore();
  };

  function initBubbleCanvas() {
    canvas = document.getElementById("cursor-bubble-canvas");
    if (!canvas) {
      canvas = document.createElement("canvas");
      canvas.id = "cursor-bubble-canvas";
      canvas.style.position = "fixed";
      canvas.style.top = "0";
      canvas.style.left = "0";
      canvas.style.width = "100vw";
      canvas.style.height = "100vh";
      canvas.style.pointerEvents = "none";
      canvas.style.zIndex = "999";
      document.body.appendChild(canvas);
    }

    ctx = canvas.getContext("2d");
    resize();
    window.addEventListener("resize", resize, { passive: true });

    // Track Mouse
    window.addEventListener("mousemove", onMouseMove, { passive: true });
    window.addEventListener("mousedown", onMouseDown, { passive: true });
    window.addEventListener("touchstart", onTouchStart, { passive: true });
    window.addEventListener("touchmove", onTouchMove, { passive: true });

    requestAnimationFrame(renderLoop);
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);
  }

  function onMouseMove(e) {
    var now = Date.now();
    var dt = Math.max(1, now - lastMoveTime);
    lastMoveTime = now;

    var dx = e.clientX - mouse.x;
    var dy = e.clientY - mouse.y;
    mouse.speed = Math.sqrt(dx * dx + dy * dy) / dt;

    mouse.lastX = mouse.x;
    mouse.lastY = mouse.y;
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.isMoving = true;

    // Spawn bubbles based on movement speed
    var spawnCount = mouse.speed > 1.2 ? Math.min(3, Math.floor(mouse.speed * 1.5)) : (Math.random() < 0.35 ? 1 : 0);
    
    for (var i = 0; i < spawnCount; i++) {
      if (particles.length < maxParticles) {
        var size = Math.random() * 10 + 5;
        // Directional momentum based on mouse movement
        var vx = -dx * 0.08 + (Math.random() - 0.5) * 1.5;
        var vy = -dy * 0.08 - (Math.random() * 1.2 + 0.4);
        particles.push(new Bubble(mouse.x, mouse.y, size, null, vx, vy));
      }
    }
  }

  function onMouseDown(e) {
    var x = e.clientX;
    var y = e.clientY;
    
    // Bubble Pop Splash Burst
    for (var i = 0; i < 6; i++) {
      if (particles.length < maxParticles) {
        var rad = Math.random() * 14 + 6;
        var angle = (Math.PI * 2 / 6) * i + (Math.random() - 0.5) * 0.5;
        var speed = Math.random() * 2.5 + 1.2;
        var vx = Math.cos(angle) * speed;
        var vy = Math.sin(angle) * speed - 1.2;
        particles.push(new Bubble(x, y, rad, null, vx, vy));
      }
    }

    // Mini spark droplets
    for (var j = 0; j < 8; j++) {
      sparkParticles.push(new Spark(x, y));
    }
  }

  function onTouchStart(e) {
    if (e.touches && e.touches.length > 0) {
      onMouseDown(e.touches[0]);
    }
  }

  function onTouchMove(e) {
    if (e.touches && e.touches.length > 0) {
      onMouseMove(e.touches[0]);
    }
  }

  function renderLoop() {
    ctx.clearRect(0, 0, width, height);

    var now = Date.now();
    
    // Ambient breathing: spawn gentle micro bubble if cursor is on screen and stationary
    if (mouse.x > 0 && mouse.y > 0 && (now - lastMoveTime > 350)) {
      ambientTimer++;
      if (ambientTimer % 22 === 0 && particles.length < maxParticles) {
        var ambientSize = Math.random() * 8 + 4;
        particles.push(new Bubble(mouse.x + (Math.random() - 0.5) * 20, mouse.y + (Math.random() - 0.5) * 20, ambientSize));
      }
    }

    // Draw active cursor glow halo
    if (mouse.x > 0 && mouse.y > 0) {
      var auraGrad = ctx.createRadialGradient(mouse.x, mouse.y, 2, mouse.x, mouse.y, 32);
      auraGrad.addColorStop(0, "rgba(244, 123, 92, 0.15)");
      auraGrad.addColorStop(0.5, "rgba(249, 199, 79, 0.06)");
      auraGrad.addColorStop(1, "rgba(255, 255, 255, 0)");
      ctx.beginPath();
      ctx.arc(mouse.x, mouse.y, 32, 0, Math.PI * 2);
      ctx.fillStyle = auraGrad;
      ctx.fill();
    }

    // Update & draw bubbles
    for (var i = particles.length - 1; i >= 0; i--) {
      var p = particles[i];
      p.update();
      p.draw(ctx);
      if (p.isDead) {
        // Pop spark chance when bubble pops naturally
        if (Math.random() < 0.4 && sparkParticles.length < 40) {
          for (var s = 0; s < 3; s++) {
            sparkParticles.push(new Spark(p.x, p.y, p.color));
          }
        }
        particles.splice(i, 1);
      }
    }

    // Update & draw spark droplets
    for (var j = sparkParticles.length - 1; j >= 0; j--) {
      var sp = sparkParticles[j];
      sp.update();
      sp.draw(ctx);
      if (sp.isDead) {
        sparkParticles.splice(j, 1);
      }
    }

    requestAnimationFrame(renderLoop);
  }

  // Initialize once DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initBubbleCanvas);
  } else {
    initBubbleCanvas();
  }

})(window, document);
