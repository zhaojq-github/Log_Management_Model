$(function () {

    $.mpb = function (action, options) {
        var settings = $.extend({state: "", value: [0, 0], position: "", speed: 20, complete: null}, options);
        if (action == "show" || action == "update") {
            if (action == "show") {
                $(".mpb").remove();
                var mpb = '<div class="mpb ' + settings.position + '">\n                               <div class="mpb-progress' + (settings.state != "" ? " mpb-" + settings.state : "") + '" style="width:' + settings.value[0] + '%;"></div>\n                           </div>';
                $("body").append(mpb)
            }
            var i = $.isArray(settings.value) ? settings.value[0] : $(".mpb .mpb-progress").width();
            var to = $.isArray(settings.value) ? settings.value[1] : settings.value;
            var timer = setInterval(function () {
                $(".mpb .mpb-progress").css("width", i + "%");
                i++;
                if (i > to) {
                    clearInterval(timer);
                    if ($.isFunction(settings.complete)) {
                        settings.complete.call(this)
                    }
                }
            }, settings.speed)
        }
        if (action == "destroy") {
            $(".mpb").remove()
        }
    };
    $.expr[":"].containsi = function (a, i, m) {
        return jQuery(a).text().toUpperCase().indexOf(m[3].toUpperCase()) >= 0
    }
});
$('input, textarea').placeholder();
