const internalInputs = document.querySelectorAll(
        'input[name="internal_marks"]'
    );

    const externalInputs = document.querySelectorAll(
        'input[name="external_marks"]'
    );

    const totalInputs = document.querySelectorAll(
        'input[name="total_marks"]'
    );


    function calculateTotal(index) {

        const internal =
            Number(internalInputs[index].value) || 0;

        const external =
            Number(externalInputs[index].value) || 0;

        totalInputs[index].value = internal + external;
    }


    internalInputs.forEach((input, index) => {

        input.addEventListener("input", function() {

            calculateTotal(index);

        });

    });


    externalInputs.forEach((input, index) => {

        input.addEventListener("input", function() {

            calculateTotal(index);

        });

    });


    internalInputs.forEach((input, index) => {

        calculateTotal(index);

    });