$(document).ready(function() {
	$(".table-checkbox tbody tr:has(:checked)").addClass("success");

	$(".table-checkbox tbody td").click(function(e) {
		if($(e.target).is("a,a *"))
			return;

		var tr = $(this).parent();
		tr.toggleClass("success");
		$("input[type=checkbox]", tr).prop("checked", tr.hasClass("success"));
	});

	$(".table-with-filter").each(function() {
		var t = $(this);

		var form = $('<form class="form-search"><input type="text" class="search-query" autocomplete="off" /></form>').insertBefore(t);
		$("input", form).attr("placeholder", i18n["Filter"]).bind("keyup click change", function() {
			var val = $(this).val().trim().toLowerCase();
			var rows = $("> tbody > tr,> tr", t);
			if(val == "")
				rows.css("display", "").find("input").prop("disabled", false);
			else
			{
				rows.each(function() {
					var contains = false;
					$("> td", this).each(function() {
						if($(this).text().toLowerCase().indexOf(val) != -1)
						{
							contains = true;
							return false;
						}
					});
					$(this).css("display", contains ? "" : "none");
					$("input", this).prop("disabled", !contains);
				});
			}
		});
	});

	$(".export-key").each(function() {
		var t = $(this);
		t.addClass("btn-group");

		var btn = $("input", t);
		var btnDropdown = $('<button class="dropdown-toggle" data-toggle="dropdown"><span class="caret"></span></button>').addClass(btn.attr("class")).insertAfter(btn);
		var dropdown = $('<ul class="dropdown-menu"></ul>').insertAfter(btnDropdown);
		var select = $("select", t).css("display", "none");
		$("option", select).each(function() {
			var option = $(this);
			$('<a href="#"></a>').text(option.text()).click(function() {
				select.val(option.attr("value"));
				btn.click();
				return false;
			}).wrap('<li/>').parent().appendTo(dropdown);
		});
		btnDropdown.dropdown();
	});

	$(".faq:not(.no-popup)").each(function() {
		var no = $(this).attr("data-faq-no");
		$("a", this).click(function() {
			var a = $(this);
			$.get(baseurl+"/faq/"+no, function(data) {
				var doc = $(data);
				var content = $(
					'<div class="modal hide fade" role="dialog">' +
						'<div class="modal-header">' +
							'<button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>' +
							'<h3>'+$("h2", doc).html()+'</h3>' +
						'</div>' +
						'<div class="modal-body">' +
							$("div.faq", doc).html() +
						'</div>' +
					'</div>'
				).on("hidden", function() {
					$(this).remove();
				}).modal();
			}, "html");

			return false;
		});
	});
});

function quoteRegexp(str) {
	return (str+'').replace(/([.?*+^$[\]\\(){}|-])/g, "\\$1");
}