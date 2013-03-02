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
});

function quoteRegexp(str) {
	return (str+'').replace(/([.?*+^$[\]\\(){}|-])/g, "\\$1");
}