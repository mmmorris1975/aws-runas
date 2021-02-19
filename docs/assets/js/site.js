const mySidebar = document.getElementById("mySidebar");
const overlayBg = document.getElementById("myOverlay");

function w3_open() {
    if (mySidebar.style.display === 'block') {
        mySidebar.style.display = 'none';
        overlayBg.style.display = "none";
    } else {
        mySidebar.style.display = 'block';
        overlayBg.style.display = "block";
    }
}

function w3_close() {
    mySidebar.style.display = "none";
    overlayBg.style.display = "none";
}

function populate_sectionNav() {
    let content = document.getElementById("content");
    let sections = content.getElementsByTagName("h3");
    let secNav = document.getElementById("sectionNav");

    if (sections.length > 0) {
        secNav.innerHTML = 'Jump to section:<a href="#top" style="padding-left: 16px;">Top</a>';

        for (let i = 0; i < sections.length; i++) {
            let id = sections[i].id;
            secNav.innerHTML = secNav.innerHTML +
                '<a href="#' + id + '" style="padding-left: 16px;">' + id + '</a>';
        }
    }
}

window.addEventListener('load', populate_sectionNav);