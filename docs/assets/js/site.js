const leftSidebar = document.getElementById("left-sidebar");
const overlayBg = document.getElementById("myOverlay");

function w3_open() {
    if (leftSidebar.style.display === 'block') {
        leftSidebar.style.display = 'none';
        overlayBg.style.display = "none";
    } else {
        leftSidebar.style.display = 'block';
        overlayBg.style.display = "block";
    }
}

function w3_close() {
    leftSidebar.style.display = "none";
    overlayBg.style.display = "none";
}

function title_case(str) {
    return str.split("-").map(function (s) {
        return s.replace(s[0], s[0].toUpperCase());
    }).join(" ")
}

function populate_sectionNav() {
    let content = document.getElementById("content");
    let sections = content.getElementsByTagName("h3");
    let secNav = document.getElementById("right-sidebar");

    if (sections.length > 0) {
        secNav.innerHTML = 'Jump to section:<a class="w3-bar-item w3-button w3-hover-theme" href="#top" style="padding-left: 16px;">Top</a>';

        for (let i = 0; i < sections.length; i++) {
            let id = sections[i].id;
            secNav.innerHTML = secNav.innerHTML +
                '<a class="w3-bar-item w3-button w3-hover-theme" href="#' + id + '" style="padding-left: 16px;">' + title_case(id) + '</a>';
        }
    }
}

window.addEventListener('load', populate_sectionNav);