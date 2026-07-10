String.prototype.toProperCase = function () {
    return this.replace(/\w\S*/g, function(txt){return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();});
};
function createAndAppendElements(data, container, dictionary, ignoredItems, pivot) {
    for (var key in data) {
        if (key == 'screenshot'){
            container.appendChild(document.createElement("hr"));
            var shot = document.createElement("div");
            var img = document.createElement("img");
            img.style.height = "100%";
            img.style.width = "100%";
            // data[key] is a base64 screenshot produced by our own server.
            img.src = "data:image/png;base64," + data[key];
            shot.appendChild(img);
            container.appendChild(shot);
        }
        else if (!ignoredItems.includes(key)) {
            container.appendChild(document.createElement("hr"));
            var item = document.createElement("div");

            var label = key in dictionary ? dictionary[key] : key.toProperCase();

            // Values below come from third-party sites, so insert them as text
            // (never innerHTML) to avoid XSS from a malicious analysed page.
            if (Array.isArray(data[key])) {
                item.appendChild(document.createTextNode(label + ": "));
                data[key].forEach(function (element) {
                    item.appendChild(document.createElement("br"));
                    if (pivot) {
                        // Turn a found value into a link that runs another tool.
                        var a = document.createElement("a");
                        a.className = "pivot-link";
                        a.href = pivot(String(element));
                        a.textContent = String(element);
                        item.appendChild(a);
                    } else {
                        item.appendChild(document.createTextNode(String(element)));
                    }
                });
            } else {
                item.appendChild(document.createTextNode(label + ": " + data[key]));
            }

            container.appendChild(item);

            if(key === "country_name")
            {
                container.appendChild(document.createElement("hr"));

                var ipmap = document.createElement("div");
                ipmap.setAttribute("id", "map")
                ipmap.setAttribute("style", "height:40vh ;width:100%;")
                container.appendChild(ipmap)

                var map = L.map('map').setView([data["latitude"], data["longitude"]], 10);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
                L.marker([data["latitude"], data["longitude"]]).addTo(map);
            }
        }
    }
}

var toolsConfig = [
    {
        containerSelector: ".cookies-info",
        dataKey: "cookies",
        dictionary: {},
        ignoredItems: []
    },
    {
        containerSelector: ".ip-information",
        dataKey: "ip_info",
        dictionary: {
            "ip" : "IP",
            "anycast" : "Anycast network architecture",
            "org" : "Organization",
            "postal" : "ZIP Code",
            "country_name" : "Country"
        },
        ignoredItems: ["isEU", "country_flag_url", "country", "country_flag", "country_currency", "continent", "loc"]
    },
    {
        containerSelector: ".header-info",
        dataKey: "headers",
        dictionary: {
            "pragma" : "Pragma (Catching) Info",
            "server" : "Web Server Info"
        },
        ignoredItems:["perf", "expiry", "set-cookie"]
    },
    {
        containerSelector:".DNS-info",
        dataKey: "dns_records",
        dictionary: {
            "A" : "'A' (address) Record",
            "NS" : "'NS' (nameserver) Record",
            "SOA" : "'SOA' (start of authority) Record",
            "MX" : "'MX' (mail exchange) Record"
        },
        ignoredItems: []
    },
    {
        containerSelector:".SSL-info",
        dataKey:"ssl_info",
        dictionary:{},
        ignoredItems:[]
    },
    {
        containerSelector:".redirects-info",
        dataKey: "redirects",
        dictionary:{"Redirects": "Redirected From"},
        ignoredItems:[]
    },
    {
        containerSelector:".sitemap-info",
        dataKey:"sitemap",
        dictionary:{},
        ignoredItems:[]
    },
    {
        containerSelector:".ports-info",
        dataKey:"port_info",
        dictionary:{},
        ignoredItems:[]
    },
    {
        containerSelector:".whois-info",
        dataKey:"whois_info",
        dictionary:{},
        ignoredItems:[]
    },
    {
        containerSelector:".links-info",
        dataKey:"link_info",
        dictionary:{},
        ignoredItems:[]
    },
    {
        containerSelector:".email-info",
        dataKey:"email_info",
        dictionary:{},
        ignoredItems:[],
        pivot:function(v){return "/email_tool?email_input=" + encodeURIComponent(v);}
    },
    {
        containerSelector:".phone-info",
        dataKey:"phone_info",
        dictionary:{},
        ignoredItems:[]
    }
];

// Slow tools are fetched after the page renders so one flaky source can't
// hold up the whole report.
var lazyTools = [
    {
        selector:".subdomain-info",
        tool:"subdomains",
        param:function(d){return "domain=" + encodeURIComponent(d.domain);},
        pivot:function(v){return "/web_tool?web_input=" + encodeURIComponent("https://" + v + "/");}
    },
    {
        selector:".wayback-info",
        tool:"wayback",
        param:function(d){return "url=" + encodeURIComponent(d.url);}
    },
    {
        selector:".screenshot-info",
        tool:"screenshot",
        param:function(d){return "url=" + encodeURIComponent(d.url);}
    }
];

document.addEventListener('DOMContentLoaded', function() {
    var largeJsonScript = document.getElementById('large-json-data');
    var largeJsonData = JSON.parse(largeJsonScript.getAttribute('data-large-json'));

    toolsConfig.forEach(function (config) {
        var container = document.querySelector(config.containerSelector);
        createAndAppendElements(largeJsonData[config.dataKey], container, config.dictionary, config.ignoredItems, config.pivot);
    });

    var lazy = document.getElementById('lazy-data');
    if (!lazy) return;
    var ctx = { domain: lazy.getAttribute('data-domain'), url: lazy.getAttribute('data-url') };

    lazyTools.forEach(function (lt) {
        var card = document.querySelector(lt.selector);
        if (!card) return;
        card.appendChild(document.createElement("hr"));
        var loading = document.createElement("div");
        loading.className = "lazy-loading";
        loading.textContent = "Loading…";
        card.appendChild(loading);

        fetch("/web_tool_data?tool=" + lt.tool + "&" + lt.param(ctx))
            .then(function (r) { return r.json(); })
            .then(function (j) {
                loading.remove();
                createAndAppendElements(j.result || {}, card, {}, [], lt.pivot);
            })
            .catch(function () { loading.textContent = "Failed to load."; });
    });
});

