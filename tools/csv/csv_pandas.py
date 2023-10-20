import pandas as pd

def filter_prepped_testtakers_by_selection_list(base_file, filter_by_file, output_file):
    '''The 'base_file' is a file created by CSV output of the "get_target_testtakers" function, whose columns are (testTakerId, regNo, asmtEventId)\n
    The 'filter_by_file' is a CSV file only with a testTakerId column.\n
    This function produces a new CSV file containing any row from the "base_file" where
    the testTakerId matches that of the "filter_by_file.\n
    This can be used to effectively collect large target data once from Dynamo, then create
    selection lists to target portions of that data, avoiding the need to create whole target files in the "base_file" format'''
    df1 = pd.read_csv(filter_by_file)  # assuming the file contains only testTakerIds
    df2 = pd.read_csv(base_file)  # the file with testTakerIds and two additional fields (asmtEventId, RegNo)
    # Merge the data using an inner join on the 'userId' column
    result = pd.merge(df1, df2, on='testTakerId', how='inner')

    result.to_csv(output_file, index=False)
