(function () {
  const lightbox = document.getElementById("lightbox");
  if (!lightbox) return;

  const img = lightbox.querySelector(".lightbox-img");
  const caption = lightbox.querySelector(".lightbox-caption");
  const counter = lightbox.querySelector(".lightbox-counter");
  const closeBtn = lightbox.querySelector(".lightbox-close");
  const backdrop = lightbox.querySelector(".lightbox-backdrop");
  const prevBtn = lightbox.querySelector(".lightbox-prev");
  const nextBtn = lightbox.querySelector(".lightbox-next");

  const gallery = Array.from(
    document.querySelectorAll(".screenshot-grid .screenshot-thumb")
  ).map(function (btn) {
    const thumb = btn.querySelector("img");
    return {
      src: thumb ? thumb.src : "",
      alt: thumb ? thumb.alt : "",
      caption: btn.getAttribute("data-caption") || (thumb ? thumb.alt : ""),
    };
  });

  let currentIndex = -1;
  let galleryMode = false;

  function showAt(index) {
    if (!gallery.length) return;
    currentIndex = (index + gallery.length) % gallery.length;
    const item = gallery[currentIndex];
    img.src = item.src;
    img.alt = item.alt;
    caption.textContent = item.caption;
    counter.textContent = (currentIndex + 1) + " / " + gallery.length;
    prevBtn.style.display = gallery.length > 1 ? "" : "none";
    nextBtn.style.display = gallery.length > 1 ? "" : "none";
    counter.style.display = gallery.length > 1 ? "" : "none";
  }

  function openGallery(index) {
    galleryMode = true;
    showAt(index);
    lightbox.classList.add("is-open");
    lightbox.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    closeBtn.focus();
  }

  function openSingle(src, alt, text) {
    galleryMode = false;
    currentIndex = -1;
    img.src = src;
    img.alt = alt || "";
    caption.textContent = text || "";
    counter.style.display = "none";
    prevBtn.style.display = "none";
    nextBtn.style.display = "none";
    lightbox.classList.add("is-open");
    lightbox.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    closeBtn.focus();
  }

  function close() {
    lightbox.classList.remove("is-open");
    lightbox.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    img.src = "";
    galleryMode = false;
    currentIndex = -1;
  }

  function step(delta) {
    if (!galleryMode || gallery.length < 2) return;
    showAt(currentIndex + delta);
  }

  document.querySelectorAll(".screenshot-grid .screenshot-thumb").forEach(function (btn, index) {
    btn.addEventListener("click", function () {
      openGallery(index);
    });
  });

  document.querySelectorAll(".screenshot-thumb--faq").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const thumb = btn.querySelector("img");
      if (!thumb) return;
      openSingle(thumb.src, thumb.alt, btn.getAttribute("data-caption") || thumb.alt);
    });
  });

  prevBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    step(-1);
  });

  nextBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    step(1);
  });

  closeBtn.addEventListener("click", close);
  backdrop.addEventListener("click", close);

  document.addEventListener("keydown", function (e) {
    if (!lightbox.classList.contains("is-open")) return;
    if (e.key === "Escape") close();
    if (galleryMode && e.key === "ArrowLeft") step(-1);
    if (galleryMode && e.key === "ArrowRight") step(1);
  });
})();
