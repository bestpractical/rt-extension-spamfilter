htmx.onLoad( function(elt) {

    // adjust the width of the checkboxes columns since it's not possible
    // to add specific class to the th element
    jQuery(elt).find('#discard_all,#not_spam_all').closest('th').css('width', '1%');

    jQuery(elt).find('#not_spam_all').change( function () {
        // toggle all checkboxes
        jQuery(elt).find('input.not_spam').prop('checked', this.checked).change();
        jQuery(elt).find('#discard_all').prop('checked', false);
    });
    jQuery(elt).find('#discard_all').change( function () {
        // toggle all checkboxes
        jQuery(elt).find('input.discard').prop('checked', this.checked).change();
        jQuery(elt).find('#not_spam_all').prop('checked', false);
    });
    // check if the corresponding Release-X or Delete-X is already checked
    // and uncheck it
    jQuery(elt).find('input.not_spam,input.discard').change( function () {
        // get id and split it
        var id = this.id.split('-');

        if (!this.checked) {
            // disable the oposite checkbox
            if (id[0] == 'Release') {
                jQuery(elt).find('#not_spam_all').prop('checked', false);
            } else {
                jQuery(elt).find('#discard_all').prop('checked', false);
            }
            return;
        } else {
            // disable the oposite checkbox
            if (id[0] == 'Release') {
                jQuery(elt).find('#Delete-' + id[1]).prop('checked', false);
                jQuery(elt).find('#discard_all').prop('checked', false);
            } else {
                jQuery(elt).find('#Release-' + id[1]).prop('checked', false);
                jQuery(elt).find('#not_spam_all').prop('checked', false);
            }
        }
    });
    // Enable shift selection of checkboxes
    lastReleaseSelected = null;
    lastDeleteSelected = null;
    ReleaseCheckboxes = jQuery(elt).find('input.not_spam');
    DeleteCheckboxes = jQuery(elt).find('input.discard');
    jQuery(elt).find('input.not_spam,input.discard').click( function (e) {
            // get id and split it
            var id = this.id.split('-');
            if (id[0] == 'Release') {
                if (!lastReleaseSelected) {
                    lastReleaseSelected = this;
                    return;
                }
                if (e.shiftKey) {
                    var start = ReleaseCheckboxes.index(this);
                    var end = ReleaseCheckboxes.index(lastReleaseSelected);
                    ReleaseCheckboxes.slice(Math.min(start,end), Math.max(start,end)+ 1).prop('checked', lastReleaseSelected.checked).change();
                }
                lastReleaseSelected = this;
            } else {
                if (!lastDeleteSelected) {
                    lastDeleteSelected = this;
                    return;
                }
                if (e.shiftKey) {
                    var start = DeleteCheckboxes.index(this);
                    var end = DeleteCheckboxes.index(lastDeleteSelected);
                    DeleteCheckboxes.slice(Math.min(start,end), Math.max(start,end)+ 1).prop('checked', lastDeleteSelected.checked).change();
                }
                lastDeleteSelected = this;
            }
    });
});
